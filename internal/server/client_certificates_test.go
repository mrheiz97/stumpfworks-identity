package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

func TestClientCertificateDisplayBoundaries(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	stamp := func(v time.Time) sql.NullTime { return sql.NullTime{Time: v, Valid: true} }
	for _, tc := range []struct {
		name, status             string
		issued, expires, created time.Time
		want                     string
	}{
		{"none", "", time.Time{}, time.Time{}, time.Time{}, "none"},
		{"valid", "active", now.Add(-time.Hour), now.Add(31 * 24 * time.Hour), now, "valid"},
		{"warning boundary", "active", now.Add(-time.Hour), now.Add(30 * 24 * time.Hour), now, "expiring"},
		{"expired boundary", "active", now.Add(-time.Hour), now, now, "expired"},
		{"future", "active", now.Add(time.Minute), now.Add(time.Hour), now, "not_yet_valid"},
		{"pending", "pending", now.Add(-time.Minute), now.Add(time.Hour), now.Add(-time.Minute), "pending"},
		{"pending deadline", "pending", now.Add(-time.Hour), now.Add(time.Hour), now.Add(-database.ClientDeviceActivationWindow), "activation_expired"},
		{"revoked", "revoked", now.Add(-time.Hour), now.Add(time.Hour), now, "revoked"},
		{"superseded", "superseded", now.Add(-time.Hour), now.Add(time.Hour), now, "superseded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := database.ClientCertificateSummary{Status: tc.status}
			if tc.status != "" {
				m.IssuedAt = stamp(tc.issued)
				m.ExpiresAt = stamp(tc.expires)
				m.CreatedAt = stamp(tc.created)
			}
			c := database.Client{ClientID: "example-client", Enabled: true, AuthMode: database.ClientAuthCertificateRequired}
			v := certificateClientView(c, m, now)
			if v.CertificateStatus != tc.want {
				t.Fatal(v)
			}
			usable := tc.want == "valid" || tc.want == "expiring"
			if (v.Attention == "") != usable {
				t.Fatal("required mode warning", v)
			}
			if m.ExpiresAt.Valid && v.ExpiresAt != m.ExpiresAt.Time.UTC().Format(time.RFC3339) {
				t.Fatal("expiry not UTC")
			}
			c.AuthMode = database.ClientAuthCertificatePreferred
			v = certificateClientView(c, m, now)
			if !strings.Contains(v.TokenPolicy, "fallback allowed") {
				t.Fatal("preferred policy unclear")
			}
			c.Enabled = false
			v = certificateClientView(c, m, now)
			if !strings.Contains(v.Attention, "disabled") {
				t.Fatal("disabled client not identified")
			}
		})
	}
}

func TestClientCertificateRoutesRolesPrivacyAndReadOnly(t *testing.T) {
	for _, role := range []adminauth.Role{adminauth.RoleAdmin, adminauth.RoleClientOperator, adminauth.RoleAuditor, adminauth.RoleOperator, adminauth.RoleOIDCOperator} {
		t.Run(string(role), func(t *testing.T) {
			s, sessions, _ := updateServerFixture(t, role)
			allowed := role == adminauth.RoleAdmin || role == adminauth.RoleClientOperator || role == adminauth.RoleAuditor
			before, err := s.store.Audits(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/clients", "/api/v1/clients/certificates"} {
				w := roleRequest(s, sessions, http.MethodGet, path)
				if !allowed {
					if w.Code != 403 {
						t.Fatal("role boundary", path, w.Code)
					}
					continue
				}
				if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(path, w.Code, w.Body.String())
				}
				body := w.Body.String()
				for _, secret := range []string{"synthetic-token", "token_hash", "fingerprint", "serial", "update-credential", "synthetic-ca", "BEGIN PRIVATE KEY"} {
					if strings.Contains(body, secret) {
						t.Fatal("private metadata exposed", secret)
					}
				}
				if path == "/clients" {
					for _, label := range []string{"Certificate required", "bearer token rejected", "Expires within 30 days", "UTC"} {
						if !strings.Contains(body, label) {
							t.Fatal("missing display", label)
						}
					}
				} else {
					var result []clientCertificateView
					if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result) != 1 || result[0].AuthMode != database.ClientAuthCertificateRequired || result[0].CertificateStatus != "expiring" {
						t.Fatal("API projection", result, err)
					}
				}
			}
			after, err := s.store.Audits(t.Context())
			if err != nil || len(after) != len(before) {
				t.Fatal("read caused mutation")
			}
		})
	}
}
func TestClientCertificateLookupFailureIsNotNoCertificate(t *testing.T) {
	s, sessions, _ := updateServerFixture(t, adminauth.RoleAuditor)
	st := s.store.(*database.Store)
	if _, err := st.DB.Exec(`DROP TABLE client_device_credentials`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/clients", "/api/v1/clients/certificates"} {
		w := roleRequest(s, sessions, "GET", path)
		if w.Code != 503 || strings.Contains(w.Body.String(), "No certificate") {
			t.Fatal("lookup error disguised", w.Code, w.Body.String())
		}
	}
}

func TestClientCertificateModeLabels(t *testing.T) {
	for _, tc := range []struct{ mode, label, policy string }{
		{database.ClientAuthTokenOnly, "Token only", "certificate authentication disabled"},
		{database.ClientAuthCertificatePreferred, "Certificate preferred", "fallback allowed"},
		{database.ClientAuthCertificateRequired, "Certificate required", "bearer token rejected"},
		{"unrecognized", "Unknown mode", "unavailable"},
	} {
		v := certificateClientView(database.Client{ClientID: "example", Enabled: true, AuthMode: tc.mode}, database.ClientCertificateSummary{}, time.Now())
		if v.AuthLabel != tc.label || !strings.Contains(v.TokenPolicy, tc.policy) {
			t.Fatal(tc.mode, v)
		}
	}
}
