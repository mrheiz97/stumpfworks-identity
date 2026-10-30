package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/config"
)

func TestClientAPIServerIsRestrictedAndRequiresVerifiedCertificates(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "device-ca.pem")
	if err := os.WriteFile(caFile, syntheticDeviceCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cfg := config.Config{Listen: "127.0.0.1:8080", TLSCertFile: "server.crt", TLSKeyFile: "server.key", ClientAPIEnabled: true, ClientAPIListen: "127.0.0.1:8444", ClientAPICAFile: caFile}
	server, err := clientAPIServer(cfg, application)
	if err != nil {
		t.Fatal(err)
	}
	if server.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || server.TLSConfig.MinVersion != tls.VersionTLS12 || server.TLSConfig.ClientCAs == nil {
		t.Fatal("client API TLS policy changed")
	}
	for _, test := range []struct {
		method, path string
		want         int
	}{{http.MethodPost, "/api/v1/client/status", http.StatusNoContent}, {http.MethodGet, "/api/v1/client/status", http.StatusMethodNotAllowed}, {http.MethodGet, "/", http.StatusNotFound}, {http.MethodGet, "/login", http.StatusNotFound}, {http.MethodGet, "/metrics", http.StatusNotFound}} {
		request := httptest.NewRequest(test.method, test.path, nil)
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("%s %s returned %d, want %d", test.method, test.path, response.Code, test.want)
		}
	}
}

func TestClientAPIHandshakeRejectsMissingUnknownAndWrongUsageCertificates(t *testing.T) {
	caCertificate, caKey, caPEM := syntheticDeviceCA(t, "Trusted device CA")
	caFile := filepath.Join(t.TempDir(), "device-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cfg := config.Config{Listen: "127.0.0.1:8080", TLSCertFile: "server.crt", TLSKeyFile: "server.key", ClientAPIEnabled: true, ClientAPIListen: "127.0.0.1:8444", ClientAPICAFile: caFile}
	configured, err := clientAPIServer(cfg, application)
	if err != nil {
		t.Fatal(err)
	}
	live := httptest.NewUnstartedServer(configured.Handler)
	live.TLS = configured.TLSConfig.Clone()
	live.StartTLS()
	defer live.Close()

	trusted := syntheticSignedClientCertificate(t, caCertificate, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	wrongUsage := syntheticSignedClientCertificate(t, caCertificate, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	unknownCA, unknownKey, _ := syntheticDeviceCA(t, "Unknown device CA")
	unknown := syntheticSignedClientCertificate(t, unknownCA, unknownKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	for _, test := range []struct {
		name        string
		certificate *tls.Certificate
		wantSuccess bool
	}{{"trusted", &trusted, true}, {"missing", nil, false}, {"unknown CA", &unknown, false}, {"wrong EKU", &wrongUsage, false}} {
		t.Run(test.name, func(t *testing.T) {
			transport := live.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			if test.certificate != nil {
				transport.TLSClientConfig.Certificates = []tls.Certificate{*test.certificate}
			}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Post(live.URL+"/api/v1/client/status", "application/json", nil)
			if test.wantSuccess {
				if err != nil || response.StatusCode != http.StatusNoContent {
					t.Fatalf("trusted client failed: response=%v err=%v", response, err)
				}
				response.Body.Close()
				return
			}
			if err == nil {
				response.Body.Close()
				t.Fatalf("untrusted client reached handler with status %d", response.StatusCode)
			}
		})
	}
}

func TestClientAPIServerDefaultsOffAndFailsClosed(t *testing.T) {
	if server, err := clientAPIServer(config.Config{}, http.NotFoundHandler()); err != nil || server != nil {
		t.Fatalf("disabled client API changed: server=%v err=%v", server, err)
	}
	for _, cfg := range []config.Config{
		{ClientAPIEnabled: true},
		{ClientAPIEnabled: true, Listen: "same", ClientAPIListen: "same", TLSCertFile: "cert", TLSKeyFile: "key", ClientAPICAFile: "ca"},
		{ClientAPIEnabled: true, Listen: "public", ClientAPIListen: "client", TLSCertFile: "cert", TLSKeyFile: "key", ClientAPICAFile: filepath.Join(t.TempDir(), "missing")},
	} {
		if server, err := clientAPIServer(cfg, http.NotFoundHandler()); err == nil || server != nil {
			t.Fatalf("invalid client API configuration accepted: %+v", cfg)
		}
	}
}

func TestClientEnrollmentServerIsSeparatelyRestricted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/client/enroll", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	application := http.Handler(mux)
	cfg := config.Config{Listen: "public", TLSCertFile: "server.crt", TLSKeyFile: "server.key", ClientAPIEnabled: true, ClientAPIListen: "mtls", ClientAPIEnrollmentEnabled: true, ClientAPIEnrollmentListen: "enrollment"}
	server, err := clientEnrollmentServer(cfg, application)
	if err != nil || server.TLSConfig.ClientAuth != tls.NoClientCert {
		t.Fatalf("valid enrollment server rejected: server=%v err=%v", server, err)
	}
	for _, test := range []struct {
		method, path string
		want         int
	}{{http.MethodPost, "/api/v1/client/enroll", http.StatusNoContent}, {http.MethodGet, "/api/v1/client/enroll", http.StatusMethodNotAllowed}, {http.MethodGet, "/login", http.StatusNotFound}} {
		request := httptest.NewRequest(test.method, test.path, nil)
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("enrollment handler returned %d", response.Code)
		}
	}
	for _, invalid := range []config.Config{
		{ClientAPIEnabled: true, ClientAPIEnrollmentEnabled: true},
		{ClientAPIEnabled: true, ClientAPIEnrollmentEnabled: true, Listen: "same", ClientAPIListen: "mtls", ClientAPIEnrollmentListen: "same", TLSCertFile: "cert", TLSKeyFile: "key"},
		{ClientAPIEnabled: true, ClientAPIEnrollmentEnabled: true, Listen: "public", ClientAPIListen: "same", ClientAPIEnrollmentListen: "same", TLSCertFile: "cert", TLSKeyFile: "key"},
	} {
		if got, err := clientEnrollmentServer(invalid, application); err == nil || got != nil {
			t.Fatalf("invalid enrollment listener accepted: %+v", invalid)
		}
	}
}

func syntheticDeviceCAPEM(t *testing.T) []byte {
	t.Helper()
	_, _, encoded := syntheticDeviceCA(t, "Synthetic device CA")
	return encoded
}

func syntheticDeviceCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func syntheticSignedClientCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usages []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw, ca.Raw}, PrivateKey: key}
}
