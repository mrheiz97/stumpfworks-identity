package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDynamicPKINITCertificate(t *testing.T) {
	issuer, csrPEM := testPKINITIssuer(t)
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := issuer.sign("alice", csr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, caPath := filepath.Join(dir, "user.crt"), filepath.Join(dir, "ca.crt")
	if err = os.WriteFile(certPath, []byte(certPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(caPath, []byte(issuer.caPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if out, e := exec.Command("openssl", "verify", "-CAfile", caPath, certPath).CombinedOutput(); e != nil {
		t.Fatalf("openssl verify: %v: %s", e, out)
	}
	out, err := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-ext", "subjectAltName").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "alice@example.test") {
		t.Fatalf("UPN SAN missing: %s", out)
	}
}

func testPKINITIssuer(t *testing.T) (*PKINITIssuer, string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test PKINIT CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	userKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice"}}, userKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &PKINITIssuer{cert: ca, key: caKey, caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), realm: "EXAMPLE.TEST", life: 10 * time.Minute}
	return issuer, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func TestPKINITSuccessFailsClosedWhenAuditCannotPersist(t *testing.T) {
	s, st := testServer(t)
	issuer, csrPEM := testPKINITIssuer(t)
	s.ConfigurePKINIT(issuer)
	grant, err := generateLoginGrantToken()
	if err != nil {
		t.Fatal(err)
	}
	s.saveLoginGrant(grant, "alice", "test-client")
	if _, err := st.DB.ExecContext(t.Context(), `CREATE TRIGGER fail_pkinit_success_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END`); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(PKINITRequest{Grant: grant, ClientID: "test-client", CSR: csrPEM})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/pkinit", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "pkinit_unavailable") {
		t.Fatalf("audit failure returned %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("audit failure exposed a PKINIT certificate")
	}
	r = httptest.NewRequest(http.MethodPost, "/api/v1/auth/pkinit", bytes.NewReader(raw))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("consumed grant was reusable after audit failure: %d %s", w.Code, w.Body.String())
	}
}
