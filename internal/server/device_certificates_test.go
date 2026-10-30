package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

func TestDeviceCertificateEnrollmentAndRenewalTransport(t *testing.T) {
	server, store := testServer(t)
	issuer, ca := testDeviceIssuer(t)
	server.ConfigureDeviceCertificateIssuer(issuer)
	ctx := t.Context()
	const clientID = "transport-client"
	const enrollmentToken = "0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := store.CreateClient(ctx, clientID, HashClientToken("existing-status-token")); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(enrollmentToken))
	now := time.Now().UTC()
	if err := store.CreateClientEnrollmentTokenWithAudit(ctx, database.ClientEnrollmentToken{ID: "transport-enrollment", ClientID: clientID, TokenHash: hex.EncodeToString(hash[:]), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}, "192.0.2.90"); err != nil {
		t.Fatal(err)
	}
	firstCSR, _ := testDeviceCSR(t)
	enrollmentBody, _ := json.Marshal(deviceEnrollmentRequest{ClientID: clientID, Token: enrollmentToken, CSR: firstCSR})
	enrollment := httptest.NewRequest(http.MethodPost, "/api/v1/client/enroll", bytes.NewReader(enrollmentBody))
	enrollment.RemoteAddr = "192.0.2.90:1234"
	enrollmentResponse := httptest.NewRecorder()
	server.ClientEnrollmentHandler().ServeHTTP(enrollmentResponse, enrollment)
	if enrollmentResponse.Code != http.StatusOK {
		t.Fatalf("enrollment returned %d: %s", enrollmentResponse.Code, enrollmentResponse.Body.String())
	}
	var issued deviceCertificateResponse
	if err := json.Unmarshal(enrollmentResponse.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	leaf := parseCertificatePEM(t, issued.Certificate)
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "urn:stumpfworks:identity:client:"+clientID || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || issued.CA == "" {
		t.Fatalf("issued certificate contract changed: %+v", leaf)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: certPool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()}); err != nil {
		t.Fatalf("issued certificate does not verify: %v", err)
	}
	activation := httptest.NewRequest(http.MethodPost, "/api/v1/client/activate", nil)
	activation.RemoteAddr = "192.0.2.90:1234"
	activation.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	activationResponse := httptest.NewRecorder()
	server.ClientAPIHandler().ServeHTTP(activationResponse, activation)
	if activationResponse.Code != http.StatusNoContent {
		t.Fatalf("activation returned %d: %s", activationResponse.Code, activationResponse.Body.String())
	}
	replay := httptest.NewRequest(http.MethodPost, "/api/v1/client/enroll", bytes.NewReader(enrollmentBody))
	replay.RemoteAddr = "192.0.2.90:1234"
	replayResponse := httptest.NewRecorder()
	server.ClientEnrollmentHandler().ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("enrollment replay returned %d", replayResponse.Code)
	}

	secondCSR, _ := testDeviceCSR(t)
	renewalBody, _ := json.Marshal(deviceRenewalRequest{CSR: secondCSR})
	renewal := httptest.NewRequest(http.MethodPost, "/api/v1/client/renew", bytes.NewReader(renewalBody))
	renewal.RemoteAddr = "192.0.2.90:1234"
	renewal.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	renewalResponse := httptest.NewRecorder()
	server.ClientAPIHandler().ServeHTTP(renewalResponse, renewal)
	if renewalResponse.Code != http.StatusOK {
		t.Fatalf("renewal returned %d: %s", renewalResponse.Code, renewalResponse.Body.String())
	}
	var renewed deviceCertificateResponse
	if err := json.Unmarshal(renewalResponse.Body.Bytes(), &renewed); err != nil {
		t.Fatal(err)
	}
	renewedLeaf := parseCertificatePEM(t, renewed.Certificate)
	credentials, err := store.ClientDeviceCredentials(ctx, clientID)
	active, pending := 0, 0
	for _, credential := range credentials {
		if credential.Status == "active" {
			active++
		}
		if credential.Status == "pending" {
			pending++
		}
	}
	if err != nil || len(credentials) != 2 || active != 1 || pending != 1 {
		t.Fatalf("renewal credential state changed: %+v %v", credentials, err)
	}
	renewActivation := httptest.NewRequest(http.MethodPost, "/api/v1/client/activate", nil)
	renewActivation.RemoteAddr = "192.0.2.90:1234"
	renewActivation.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{renewedLeaf}, VerifiedChains: [][]*x509.Certificate{{renewedLeaf, ca}}}
	renewActivationResponse := httptest.NewRecorder()
	server.ClientAPIHandler().ServeHTTP(renewActivationResponse, renewActivation)
	if renewActivationResponse.Code != http.StatusNoContent {
		t.Fatalf("renewal activation returned %d: %s", renewActivationResponse.Code, renewActivationResponse.Body.String())
	}
	renewalReplay := httptest.NewRequest(http.MethodPost, "/api/v1/client/renew", bytes.NewReader(renewalBody))
	renewalReplay.RemoteAddr = "192.0.2.90:1234"
	renewalReplay.TLS = renewal.TLS
	renewalReplayResponse := httptest.NewRecorder()
	server.ClientAPIHandler().ServeHTTP(renewalReplayResponse, renewalReplay)
	if renewalReplayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("superseded certificate renewed again: %d", renewalReplayResponse.Code)
	}
}

func testDeviceIssuer(t *testing.T) (*DeviceCertificateIssuer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Identity Device CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "ca.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	issuer, err := LoadDeviceCertificateIssuer(certFile, keyFile, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, ca
}

func testDeviceCSR(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})), key
}

func parseCertificatePEM(t *testing.T, value string) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatal("invalid certificate response PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func certPool(certificate *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return pool
}
