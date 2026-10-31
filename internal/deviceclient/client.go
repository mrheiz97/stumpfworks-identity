package deviceclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const clientURIPrefix = "urn:stumpfworks:identity:client:"

type certificateResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	ExpiresAt   string `json:"expires_at"`
}

type Material struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	CAPEM          []byte
	ExpiresAt      time.Time
}

func HTTPClient(serverCAFile, certificateFile, keyFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if serverCAFile != "" {
		caPEM, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, err
		}
		if len(caPEM) == 0 || len(caPEM) > 1<<20 || !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("server CA file contains no certificates")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if certificateFile != "" || keyFile != "" {
		if certificateFile == "" || keyFile == "" {
			return nil, errors.New("both device certificate and key files are required")
		}
		certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
		if err != nil {
			return nil, errors.New("device credential could not be loaded")
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}

func Enroll(ctx context.Context, client *http.Client, server, clientID, token string) (Material, error) {
	if !validHTTPS(server) || !validClientID(clientID) || len(token) < 32 || len(token) > 256 {
		return Material{}, errors.New("invalid device enrollment configuration")
	}
	key, csrPEM, err := newCSR()
	if err != nil {
		return Material{}, err
	}
	payload := map[string]string{"client_id": clientID, "enrollment_token": token, "csr": string(csrPEM)}
	return requestCertificate(ctx, client, strings.TrimRight(server, "/")+"/api/v1/client/enroll", payload, clientID, key, nil)
}

func Renew(ctx context.Context, client *http.Client, server, clientID string, expectedCAPEM []byte) (Material, error) {
	if !validHTTPS(server) || !validClientID(clientID) {
		return Material{}, errors.New("invalid device renewal configuration")
	}
	if len(expectedCAPEM) == 0 || len(expectedCAPEM) > 1<<20 {
		return Material{}, errors.New("pinned device CA is required for renewal")
	}
	key, csrPEM, err := newCSR()
	if err != nil {
		return Material{}, err
	}
	payload := map[string]string{"csr": string(csrPEM)}
	return requestCertificate(ctx, client, strings.TrimRight(server, "/")+"/api/v1/client/renew", payload, clientID, key, expectedCAPEM)
}

func Activate(ctx context.Context, client *http.Client, server string) error {
	if client == nil || !validHTTPS(server) {
		return errors.New("invalid device activation configuration")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/api/v1/client/activate", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("device activation server returned HTTP %d", response.StatusCode)
	}
	return nil
}

func requestCertificate(ctx context.Context, client *http.Client, endpoint string, payload map[string]string, clientID string, key *ecdsa.PrivateKey, expectedCAPEM []byte) (Material, error) {
	if client == nil {
		return Material{}, errors.New("HTTP client is required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Material{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Material{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return Material{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Material{}, fmt.Errorf("device certificate server returned HTTP %d", response.StatusCode)
	}
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, (128<<10)+1))
	if err != nil || len(responseBytes) > 128<<10 {
		return Material{}, errors.New("device certificate response is invalid")
	}
	var issued certificateResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&issued) != nil {
		return Material{}, errors.New("device certificate response is invalid")
	}
	return validateMaterial(issued, clientID, key, expectedCAPEM)
}

func validateMaterial(response certificateResponse, clientID string, key *ecdsa.PrivateKey, expectedCAPEM []byte) (Material, error) {
	certificateBlock, certificateRest := pem.Decode([]byte(response.Certificate))
	caBlock, caRest := pem.Decode([]byte(response.CA))
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(certificateRest)) != 0 || caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(caRest)) != 0 {
		return Material{}, errors.New("device certificate response contains invalid PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return Material{}, err
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA {
		return Material{}, errors.New("device CA response is invalid")
	}
	if len(expectedCAPEM) != 0 {
		expectedBlock, rest := pem.Decode(expectedCAPEM)
		if expectedBlock == nil || expectedBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || subtle.ConstantTimeCompare(expectedBlock.Bytes, ca.Raw) != 1 {
			return Material{}, errors.New("renewal device CA does not match pinned CA")
		}
	}
	issuedKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || issuedKey.Curve != elliptic.P256() || issuedKey.X.Cmp(key.X) != 0 || issuedKey.Y.Cmp(key.Y) != 0 || len(certificate.URIs) != 1 || certificate.URIs[0].String() != clientURIPrefix+clientID || len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		return Material{}, errors.New("device certificate identity or key does not match")
	}
	clientAuth := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return Material{}, errors.New("device certificate is missing client authentication usage")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()}); err != nil {
		return Material{}, errors.New("device certificate verification failed")
	}
	expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt)
	if err != nil || !expiresAt.Equal(certificate.NotAfter) {
		return Material{}, errors.New("device certificate expiry does not match")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Material{}, err
	}
	return Material{CertificatePEM: pem.EncodeToMemory(certificateBlock), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), CAPEM: pem.EncodeToMemory(caBlock), ExpiresAt: expiresAt.UTC()}, nil
}

func WriteBundle(bundlePath, caPath string, material Material, replace bool) error {
	if bundlePath == "" || caPath == "" || len(material.CertificatePEM) == 0 || len(material.PrivateKeyPEM) == 0 || len(material.CAPEM) == 0 {
		return errors.New("complete device material and paths are required")
	}
	if _, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM); err != nil {
		return errors.New("device certificate and private key do not match")
	}
	caBlock, rest := pem.Decode(material.CAPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("device CA material is invalid")
	}
	if ca, err := x509.ParseCertificate(caBlock.Bytes); err != nil || !ca.IsCA {
		return errors.New("device CA material is invalid")
	}
	if !replace {
		for _, path := range []string{bundlePath, caPath} {
			if _, err := os.Lstat(path); err == nil {
				return errors.New("device credential material already exists")
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if replace {
		previous, err := os.ReadFile(bundlePath)
		if err != nil {
			return err
		}
		if _, err = tls.X509KeyPair(previous, previous); err != nil {
			return errors.New("existing device credential bundle is invalid")
		}
		if err = atomicWrite(bundlePath+".previous", previous, 0o600); err != nil {
			return err
		}
	}
	if err := atomicWrite(caPath, material.CAPEM, 0o644); err != nil {
		return err
	}
	bundle := append(append([]byte{}, material.CertificatePEM...), material.PrivateKeyPEM...)
	return atomicWrite(bundlePath, bundle, 0o600)
}

func RollbackBundle(bundlePath, caPath string, enrollment bool) error {
	if bundlePath == "" || caPath == "" {
		return errors.New("device material paths are required")
	}
	if enrollment {
		bundleErr := os.Remove(bundlePath)
		if bundleErr != nil && !errors.Is(bundleErr, os.ErrNotExist) {
			return bundleErr
		}
		caErr := os.Remove(caPath)
		if caErr != nil && !errors.Is(caErr, os.ErrNotExist) {
			return caErr
		}
		return nil
	}
	previous, err := os.ReadFile(bundlePath + ".previous")
	if err != nil {
		return err
	}
	if _, err = tls.X509KeyPair(previous, previous); err != nil {
		return errors.New("previous device credential bundle is invalid")
	}
	return atomicWrite(bundlePath, previous, 0o600)
}

func atomicWrite(path string, value []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".stumpfworks-device-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(mode); err == nil {
		_, err = temporary.Write(value)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func newCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

func validHTTPS(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validClientID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
