package deviceclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestEnrollValidatesAndWritesRootOnlyBundle(t *testing.T) {
	ca, caKey, caPEM := syntheticCA(t)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://identity.example.test:8445/api/v1/client/enroll" {
			t.Fatalf("unexpected endpoint: %s", request.URL)
		}
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["client_id"] != "wyse01-greeter" || payload["enrollment_token"] != strings.Repeat("t", 32) {
			t.Fatal("enrollment payload changed")
		}
		csrBlock, _ := pem.Decode([]byte(payload["csr"]))
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Fatal("client sent invalid CSR")
		}
		response := signedResponse(t, ca, caKey, caPEM, csr.PublicKey, "wyse01-greeter")
		encoded, _ := json.Marshal(response)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header)}, nil
	})}
	material, err := Enroll(context.Background(), client, "https://identity.example.test:8445", "wyse01-greeter", strings.Repeat("t", 32))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	bundle, caFile := filepath.Join(directory, "device.pem"), filepath.Join(directory, "device-ca.pem")
	if err := WriteBundle(bundle, caFile, material, false); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsKeyPair(bundle); err != nil {
		t.Fatalf("written bundle is not a matching key pair: %v", err)
	}
	info, err := os.Stat(bundle)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle permissions changed: %v %v", info, err)
	}
	if err := WriteBundle(bundle, caFile, material, false); err == nil {
		t.Fatal("enrollment overwrote an existing device credential")
	}
	before, _ := os.ReadFile(bundle)
	invalid := material
	invalid.PrivateKeyPEM = []byte("not-a-private-key")
	if err := WriteBundle(bundle, caFile, invalid, true); err == nil {
		t.Fatal("invalid renewal material was installed")
	}
	after, _ := os.ReadFile(bundle)
	if !bytes.Equal(before, after) {
		t.Fatal("failed renewal changed the existing credential bundle")
	}
}

func TestEnrollRejectsWrongIssuedIdentity(t *testing.T) {
	ca, caKey, caPEM := syntheticCA(t)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload map[string]string
		_ = json.NewDecoder(request.Body).Decode(&payload)
		csrBlock, _ := pem.Decode([]byte(payload["csr"]))
		csr, _ := x509.ParseCertificateRequest(csrBlock.Bytes)
		encoded, _ := json.Marshal(signedResponse(t, ca, caKey, caPEM, csr.PublicKey, "another-client"))
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header)}, nil
	})}
	if _, err := Enroll(context.Background(), client, "https://identity.example.test:8445", "wyse01-greeter", strings.Repeat("t", 32)); err == nil {
		t.Fatal("wrong issued device identity accepted")
	}
}

func TestRenewPinsExistingDeviceCA(t *testing.T) {
	ca, caKey, caPEM := syntheticCA(t)
	_, _, differentCAPEM := syntheticCA(t)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload map[string]string
		_ = json.NewDecoder(request.Body).Decode(&payload)
		csrBlock, _ := pem.Decode([]byte(payload["csr"]))
		csr, _ := x509.ParseCertificateRequest(csrBlock.Bytes)
		encoded, _ := json.Marshal(signedResponse(t, ca, caKey, caPEM, csr.PublicKey, "wyse01-greeter"))
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header)}, nil
	})}
	if _, err := Renew(context.Background(), client, "https://identity.example.test:8444", "wyse01-greeter", differentCAPEM); err == nil {
		t.Fatal("renewal accepted a device CA different from the pinned CA")
	}
	if _, err := Renew(context.Background(), client, "https://identity.example.test:8444", "wyse01-greeter", caPEM); err != nil {
		t.Fatalf("renewal rejected the pinned device CA: %v", err)
	}
}

func syntheticCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(raw)
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func signedResponse(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte, publicKey any, clientID string) certificateResponse {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	identity, _ := url.Parse(clientURIPrefix + clientID)
	template := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity}}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return certificateResponse{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), CA: string(caPEM), ExpiresAt: template.NotAfter.Format(time.RFC3339)}
}

func tlsKeyPair(bundle string) (any, error) {
	certificatePEM, err := os.ReadFile(bundle)
	if err != nil {
		return nil, err
	}
	certificateBlock, rest := pem.Decode(certificatePEM)
	keyBlock, _ := pem.Decode(rest)
	if certificateBlock == nil || keyBlock == nil {
		return nil, io.ErrUnexpectedEOF
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	private := key.(*ecdsa.PrivateKey)
	public := certificate.PublicKey.(*ecdsa.PublicKey)
	if public.X.Cmp(private.X) != 0 || public.Y.Cmp(private.Y) != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return key, nil
}
