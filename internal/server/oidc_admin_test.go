package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

func oidcAdminTestServer(t *testing.T) (*Server, *adminauth.Sessions, *http.Cookie) {
	t.Helper()
	_, store := testServer(t)
	sessions, err := adminauth.NewSessions("01234567890123456789012345678901", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeDirectory{}, sessions)
	form := strings.NewReader("username=alice-admin&password=correct")
	req := httptest.NewRequest(http.MethodPost, "/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusSeeOther || len(response.Result().Cookies()) != 1 {
		t.Fatalf("login returned %d", response.Code)
	}
	return s, sessions, response.Result().Cookies()[0]
}

func postOIDCAdmin(t *testing.T, s *Server, cookie *http.Cookie, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	return response
}

func TestOIDCClientAdministration(t *testing.T) {
	s, sessions, cookie := oidcAdminTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/oidc-clients", nil)
	unauthenticated := httptest.NewRecorder()
	s.Handler().ServeHTTP(unauthenticated, req)
	if unauthenticated.Code != http.StatusSeeOther || unauthenticated.Header().Get("Location") != "/login" {
		t.Fatal("OIDC client page was not protected")
	}

	missingCSRF := postOIDCAdmin(t, s, cookie, "/oidc-clients", url.Values{"client_id": {"app"}})
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF returned %d", missingCSRF.Code)
	}

	values := url.Values{
		"_csrf": {sessions.CSRF(cookie.Value)}, "client_id": {"example-app"},
		"redirect_uris": {"https://app.example.test/callback"}, "scopes": {"openid profile"},
	}
	created := postOIDCAdmin(t, s, cookie, "/oidc-clients", values)
	if created.Code != http.StatusOK {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	secretPattern := regexp.MustCompile(`<code id="oidc-client-secret">([^<]+)</code>`)
	match := secretPattern.FindStringSubmatch(created.Body.String())
	if len(match) != 2 {
		t.Fatal("created secret was not shown exactly once")
	}
	secret := match[1]
	client, err := s.store.OIDCClientByID(t.Context(), "example-app")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret)) != nil {
		t.Fatal("stored client hash does not match the disclosed secret")
	}
	if strings.Contains(created.Body.String(), client.SecretHash) {
		t.Fatal("secret hash leaked into client page")
	}

	req = httptest.NewRequest(http.MethodGet, "/oidc-clients", nil)
	req.AddCookie(cookie)
	listed := httptest.NewRecorder()
	s.Handler().ServeHTTP(listed, req)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "example-app") {
		t.Fatal("client was not listed")
	}
	if strings.Contains(listed.Body.String(), secret) || strings.Contains(listed.Body.String(), client.SecretHash) {
		t.Fatal("client listing retained secret material")
	}
	if listed.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("client page may be cached")
	}

	rotated := postOIDCAdmin(t, s, cookie, "/oidc-clients/example-app/rotate-secret", url.Values{"_csrf": {sessions.CSRF(cookie.Value)}})
	rotatedMatch := secretPattern.FindStringSubmatch(rotated.Body.String())
	if rotated.Code != http.StatusOK || len(rotatedMatch) != 2 || rotatedMatch[1] == secret {
		t.Fatal("secret rotation did not disclose one new secret")
	}
	client, _ = s.store.OIDCClientByID(t.Context(), "example-app")
	if bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(rotatedMatch[1])) != nil {
		t.Fatal("rotated secret was not committed")
	}

	disabled := postOIDCAdmin(t, s, cookie, "/oidc-clients/example-app/disable", url.Values{"_csrf": {sessions.CSRF(cookie.Value)}})
	if disabled.Code != http.StatusSeeOther {
		t.Fatalf("disable returned %d", disabled.Code)
	}
	client, _ = s.store.OIDCClientByID(t.Context(), "example-app")
	if client.Enabled {
		t.Fatal("client remained enabled")
	}

	audits, err := s.store.Audits(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"oidc_client_created": false, "oidc_client_secret_rotated": false, "oidc_client_disabled": false}
	for _, audit := range audits {
		if _, ok := want[audit.EventType]; ok && audit.ClientID == "example-app" {
			want[audit.EventType] = true
		}
	}
	for event, found := range want {
		if !found {
			t.Fatalf("missing audit event %s", event)
		}
	}
}

func TestOIDCClientCreationAuditFailureDoesNotDiscloseOrPersistSecret(t *testing.T) {
	_, sessions, cookie := oidcAdminTestServer(t)
	// testServer always provides SQLite; trigger every audit insert failure after admin login.
	_, rawStore := testServer(t)
	s := NewProtected(rawStore, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeDirectory{}, sessions)
	// The cookie remains cryptographically valid because both servers share this test session signer.
	if _, err := rawStore.DB.ExecContext(t.Context(), `CREATE TRIGGER fail_oidc_admin_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END`); err != nil {
		t.Fatal(err)
	}
	values := url.Values{"_csrf": {sessions.CSRF(cookie.Value)}, "client_id": {"failed-app"}, "redirect_uris": {"https://app.example.test/callback"}, "scopes": {"openid"}}
	response := postOIDCAdmin(t, s, cookie, "/oidc-clients", values)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "oidc-client-secret") {
		t.Fatalf("audit failure returned %d or disclosed a secret", response.Code)
	}
	if _, err := rawStore.OIDCClientByID(t.Context(), "failed-app"); err == nil {
		t.Fatal("client persisted despite audit failure")
	}
}
