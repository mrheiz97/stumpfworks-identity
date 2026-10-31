package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

func TestClientStatusCertificateModes(t *testing.T) {
	server, store := testServer(t)
	ctx := t.Context()
	const clientID = "certificate-status-client"
	const token = "synthetic-existing-status-token"
	if _, err := store.CreateClient(ctx, clientID, HashClientToken(token)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	certificate := statusClientCertificate(t, clientID, now)
	fingerprint := sha256.Sum256(certificate.Raw)
	enrollmentHash := strings.Repeat("a", 64)
	if err := store.CreateClientEnrollmentTokenWithAudit(ctx, database.ClientEnrollmentToken{ID: "status-certificate-enrollment", ClientID: clientID, TokenHash: enrollmentHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}, "192.0.2.70"); err != nil {
		t.Fatal(err)
	}
	credential := database.ClientDeviceCredential{ID: "status-certificate-credential", ClientID: clientID, FingerprintSHA256: hex.EncodeToString(fingerprint[:]), Serial: "2a", URISAN: "urn:stumpfworks:identity:client:" + clientID, PublicKeyAlgorithm: "ECDSA-P256", IssuerID: "synthetic-device-ca", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	if err := store.EnrollClientDeviceCredentialWithAudit(ctx, enrollmentHash, now, credential, "192.0.2.70"); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateClientDeviceCredentialWithAudit(ctx, clientID, credential.ID, "192.0.2.70", now); err != nil {
		t.Fatal(err)
	}
	bodyBytes, err := json.Marshal(ClientStatusRequest{ClientID: clientID, Version: "1.12.0-dev", NetworkStatus: "ok", ADStatus: "ok", CameraStatus: "ok", KerberosStatus: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(bearer string, state *tls.ConnectionState) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/client/status", strings.NewReader(string(bodyBytes)))
		r.TLS = state
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	verified := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}

	if err := store.SetClientAuthenticationModeWithAudit(ctx, clientID, database.ClientAuthCertificatePreferred, "192.0.2.70", now); err != nil {
		t.Fatal(err)
	}
	if w := request("", verified); w.Code != http.StatusNoContent {
		t.Fatalf("preferred certificate returned %d: %s", w.Code, w.Body.String())
	}
	if w := request(token, nil); w.Code != http.StatusNoContent {
		t.Fatalf("preferred token fallback returned %d: %s", w.Code, w.Body.String())
	}
	var fallbackAudits int
	if err := store.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE event_type='client_certificate_token_fallback' AND client_id=? AND success=1`, clientID).Scan(&fallbackAudits); err != nil || fallbackAudits != 1 {
		t.Fatalf("preferred token fallback audit changed: count=%d err=%v", fallbackAudits, err)
	}
	if w := request(token, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("unverified presented certificate downgraded to bearer: %d", w.Code)
	}
	if err := store.SetClientAuthenticationModeWithAudit(ctx, clientID, database.ClientAuthCertificateRequired, "192.0.2.70", now); err != nil {
		t.Fatal(err)
	}
	if w := request(token, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("required mode accepted bearer: %d", w.Code)
	}
	if w := request("", verified); w.Code != http.StatusNoContent {
		t.Fatalf("required mode rejected certificate: %d", w.Code)
	}
	if err := store.SetClientAuthenticationModeWithAudit(ctx, clientID, database.ClientAuthTokenOnly, "192.0.2.70", now); err != nil {
		t.Fatal(err)
	}
	if w := request("", verified); w.Code != http.StatusUnauthorized {
		t.Fatalf("token-only mode accepted certificate: %d", w.Code)
	}
}

func statusClientCertificate(t *testing.T, clientID string, now time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse("urn:stumpfworks:identity:client:" + clientID)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
