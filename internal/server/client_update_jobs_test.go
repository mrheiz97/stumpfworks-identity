package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

func updateServerFixture(t *testing.T, role adminauth.Role) (*Server, *adminauth.Sessions, *tls.ConnectionState) {
	t.Helper()
	s, sessions := protectedRoleServer(t, roleDirectory{roles: []adminauth.Role{role}})
	st := s.store.(*database.Store)
	ctx := t.Context()
	now := time.Now().Truncate(time.Second)
	client := "managed-update-client"
	if _, e := st.CreateClient(ctx, client, HashClientToken("synthetic-token")); e != nil {
		t.Fatal(e)
	}
	certificate := statusClientCertificate(t, client, now)
	fp := sha256.Sum256(certificate.Raw)
	tokenHash := strings.Repeat("a", 64)
	if e := st.CreateClientEnrollmentTokenWithAudit(ctx, database.ClientEnrollmentToken{ID: "update-enrollment", ClientID: client, TokenHash: tokenHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}, ""); e != nil {
		t.Fatal(e)
	}
	cred := database.ClientDeviceCredential{ID: "update-credential", ClientID: client, FingerprintSHA256: hex.EncodeToString(fp[:]), Serial: "2a", URISAN: "urn:stumpfworks:identity:client:" + client, PublicKeyAlgorithm: "ECDSA-P256", IssuerID: "synthetic-ca", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	if e := st.EnrollClientDeviceCredentialWithAudit(ctx, tokenHash, now, cred, ""); e != nil {
		t.Fatal(e)
	}
	if e := st.ActivateClientDeviceCredentialWithAudit(ctx, client, cred.ID, "", now); e != nil {
		t.Fatal(e)
	}
	if e := st.SetClientAuthenticationModeWithAudit(ctx, client, database.ClientAuthCertificateRequired, "", now); e != nil {
		t.Fatal(e)
	}
	data := []byte("approved test bytes")
	digest := sha256.Sum256(data)
	release := clientupdate.ApprovedRelease{ID: "approved-release-0001", SHA256: hex.EncodeToString(digest[:]), Manifest: clientupdate.Manifest{ReleaseVersion: "1.99.0"}, Package: data}
	s.ConfigureUpdateCatalog(clientupdate.Catalog{release.ID: release})
	return s, sessions, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
}
func updateForm(id string) url.Values {
	now := time.Now().UTC().Truncate(time.Second)
	return url.Values{"id": {id}, "client_id": {"managed-update-client"}, "release_id": {"approved-release-0001"}, "not_before": {now.Add(-time.Second).Format(time.RFC3339)}, "expires_at": {now.Add(time.Hour).Format(time.RFC3339)}}
}
func updateAdminRequest(s *Server, sessions *adminauth.Sessions, path string, form url.Values, csrf bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token := sessions.Issue("alice", time.Now())
	r.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: token})
	if csrf {
		r.Header.Set("X-CSRF-Token", sessions.CSRF(token))
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func updateDeviceRequest(s *Server, state *tls.ConnectionState, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/client/updates/"+path, strings.NewReader(body))
	r.TLS = state
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer synthetic-token")
	w := httptest.NewRecorder()
	s.ClientAPIHandler().ServeHTTP(w, r)
	return w
}
func TestUpdateAdministrationRolesCSRFAndValidation(t *testing.T) {
	for _, role := range []adminauth.Role{adminauth.RoleAdmin, adminauth.RoleClientOperator, adminauth.RoleAuditor, adminauth.RoleOperator, adminauth.RoleOIDCOperator} {
		t.Run(string(role), func(t *testing.T) {
			s, sessions, _ := updateServerFixture(t, role)
			allowed := role == adminauth.RoleAdmin || role == adminauth.RoleClientOperator
			w := updateAdminRequest(s, sessions, "/client-updates", updateForm("web-update-job-0001"), true)
			if allowed && w.Code != 303 || !allowed && w.Code != 403 {
				t.Fatal("role write boundary", w.Code, w.Body.String())
			}
			if allowed {
				if w := updateAdminRequest(s, sessions, "/client-updates", updateForm("web-update-job-0002"), false); w.Code != 403 {
					t.Fatal("CSRF accepted", w.Code)
				}
				for _, field := range []string{"release_id", "not_before", "expires_at", "maintenance", "download_url"} {
					form := updateForm("web-update-job-0002")
					form.Set(field, "invalid")
					if w := updateAdminRequest(s, sessions, "/client-updates", form, true); w.Code != 400 {
						t.Fatal("invalid field accepted", field, w.Code)
					}
				}
				form := updateForm("web-update-job-0002")
				form["client_id"] = []string{"managed-update-client", "another-client"}
				if w := updateAdminRequest(s, sessions, "/client-updates", form, true); w.Code != 400 {
					t.Fatal("duplicate form value accepted")
				}
				if w := updateAdminRequest(s, sessions, "/client-updates/web-update-job-0001/cancel", url.Values{}, true); w.Code != 303 {
					t.Fatal("cancel", w.Code)
				}
			}
			page := roleRequest(s, sessions, "GET", "/client-updates")
			if role == adminauth.RoleAuditor {
				if page.Code != 200 || !strings.Contains(page.Body.String(), "Read-only view") || strings.Contains(page.Body.String(), "Schedule update</button>") {
					t.Fatal("auditor UI")
				}
			}
		})
	}
}
func TestUpdateDeviceOwnershipAuditAndIdempotentResults(t *testing.T) {
	s, sessions, verified := updateServerFixture(t, adminauth.RoleClientOperator)
	id := "web-update-job-0001"
	form := updateForm(id)
	for i := 0; i < 2; i++ {
		if w := updateAdminRequest(s, sessions, "/client-updates", form, true); w.Code != 303 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, tlsState := range []*tls.ConnectionState{nil, {PeerCertificates: verified.PeerCertificates}} {
		if w := updateDeviceRequest(s, tlsState, "poll", ""); w.Code != 401 {
			t.Fatal("unverified device accepted", w.Code)
		}
	}
	if w := updateDeviceRequest(s, verified, "poll", ""); w.Code != 200 {
		t.Fatal("poll", w.Code, w.Body.String())
	}
	if w := updateDeviceRequest(s, verified, id+"/package", ""); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), []byte("approved test bytes")) {
		t.Fatal("download", w.Code)
	}
	for i := 0; i < 2; i++ {
		if w := updateDeviceRequest(s, verified, id+"/start", ""); w.Code != 204 {
			t.Fatal("start", w.Code, w.Body.String())
		}
	}
	if w := updateAdminRequest(s, sessions, "/client-updates/"+id+"/cancel", url.Values{}, true); w.Code != 409 {
		t.Fatal("cancel after start")
	}
	for _, body := range []string{`{"state":"succeeded","rollback_available":true,"command":"bad"}`, `{"state":"succeeded"} {}`, `{"state":"scheduled"}`} {
		if w := updateDeviceRequest(s, verified, id+"/result", body); w.Code != 400 {
			t.Fatal("invalid result accepted", w.Code)
		}
	}
	for i := 0; i < 2; i++ {
		if w := updateDeviceRequest(s, verified, id+"/result", `{"state":"succeeded","rollback_available":true}`); w.Code != 204 {
			t.Fatal("result", w.Code, w.Body.String())
		}
	}
	if w := updateDeviceRequest(s, verified, id+"/result", `{"state":"failed","rollback_available":true}`); w.Code != 409 {
		t.Fatal("conflicting result accepted")
	}
	if w := updateDeviceRequest(s, verified, "poll", ""); w.Code != 204 {
		t.Fatal("terminal job redelivered")
	}
	audits, e := s.store.Audits(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	for _, event := range []string{"client_update_scheduled", "client_update_dispatched", "client_update_succeeded"} {
		n := 0
		for _, a := range audits {
			if a.EventType == event {
				n++
				if a.Details != "job="+id {
					t.Fatal("unexpected audit payload", a.Details)
				}
			}
		}
		if n != 1 {
			t.Fatal("duplicate audit", event, n)
		}
	}
	st := s.store.(*database.Store)
	if _, e = st.DB.Exec(`UPDATE clients SET enabled=0 WHERE client_id='managed-update-client'`); e != nil {
		t.Fatal(e)
	}
	if w := updateDeviceRequest(s, verified, "poll", ""); w.Code != 401 {
		t.Fatal("disabled device accepted")
	}
}
func TestUpdateMaintenanceAndCatalogWithdrawal(t *testing.T) {
	s, sessions, verified := updateServerFixture(t, adminauth.RoleAdmin)
	release := s.updateCatalog["approved-release-0001"]
	release.RequiresMaintenance = true
	s.updateCatalog[release.ID] = release
	form := updateForm("maintenance-job-001")
	if w := updateAdminRequest(s, sessions, "/client-updates", form, true); w.Code != 400 {
		t.Fatal("greeter without window")
	}
	form.Set("maintenance", "confirmed")
	if w := updateAdminRequest(s, sessions, "/client-updates", form, true); w.Code != 303 {
		t.Fatal(w.Code)
	}
	s.ConfigureUpdateCatalog(clientupdate.Catalog{})
	if w := updateDeviceRequest(s, verified, "maintenance-job-001/start", ""); w.Code != 409 {
		t.Fatal("withdrawn release executed")
	}
	// Update routes are confined to the device listener, not the bootstrap API.
	req := httptest.NewRequest("POST", "/api/v1/client/updates/poll", nil)
	req.TLS = verified
	w := httptest.NewRecorder()
	s.ClientEnrollmentHandler().ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatal("bootstrap update exposure")
	}
	j, _ := s.store.ClientUpdateJobs(t.Context(), "managed-update-client")
	raw, _ := json.Marshal(j)
	if strings.Contains(string(raw), "token") || strings.Contains(string(raw), "command") {
		t.Fatal("secret or command in job")
	}
}
