package server

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
)

func emergencyTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestEmergencyAdministratorEndToEnd(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sessions, _ := adminauth.NewSessions("01234567890123456789012345678901", time.Hour)
	server := NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), roleDirectory{err: directory.ErrNotAuthorized}, sessions)
	server.ConfigureEmergencyAdmin(true)
	now := time.Now().UTC()
	const token = "synthetic-emergency-token-at-least-32-bytes"
	grant := database.EmergencyAdminGrant{ID: "browser-emergency-grant", TokenHash: emergencyTokenHash(token), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	if err = store.CreateEmergencyAdminGrantWithAudit(t.Context(), grant, ""); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"token": {token}}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/emergency-login", strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("emergency login returned %d: %s", response.Code, response.Body.String())
	}
	var cookie *http.Cookie
	for _, candidate := range response.Result().Cookies() {
		if candidate.Name == "swbadge_emergency_admin" {
			cookie = candidate
		}
	}
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 || cookie.MaxAge > 900 {
		t.Fatalf("invalid emergency cookie: %+v", cookie)
	}
	if strings.Contains(cookie.Value, token) {
		t.Fatal("emergency cookie exposed one-time token")
	}

	request = httptest.NewRequest(http.MethodGet, "/audit", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Audit log") {
		t.Fatalf("emergency session lacked administrator access: %d", response.Code)
	}

	replay := httptest.NewRequest(http.MethodPost, "/emergency-login", strings.NewReader(form))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusSeeOther || replayResponse.Header().Get("Location") != "/emergency-login?error=1" {
		t.Fatalf("replay returned %d %s", replayResponse.Code, replayResponse.Header().Get("Location"))
	}

	if err = store.RevokeEmergencyAdminGrantWithAudit(t.Context(), grant.ID, ""); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked emergency session returned %d", response.Code)
	}
}

func TestEmergencyLoginRejectsExpiredGrant(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sessions, _ := adminauth.NewSessions("01234567890123456789012345678901", time.Hour)
	server := NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeDirectory{}, sessions)
	server.ConfigureEmergencyAdmin(true)
	const token = "expired-emergency-token-at-least-32-bytes"
	now := time.Now().UTC()
	grant := database.EmergencyAdminGrant{ID: "expired-emergency-grant", TokenHash: emergencyTokenHash(token), CreatedAt: now.Add(-20 * time.Minute), ExpiresAt: now.Add(-time.Minute)}
	if err = store.CreateEmergencyAdminGrantWithAudit(t.Context(), grant, ""); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/emergency-login", strings.NewReader(url.Values{"token": {token}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/emergency-login?error=1" {
		t.Fatalf("expired grant returned %d", response.Code)
	}
}

func TestEmergencyLoginRouteIsAbsentByDefault(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sessions, _ := adminauth.NewSessions("01234567890123456789012345678901", time.Hour)
	server := NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeDirectory{}, sessions)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := httptest.NewRequest(method, "/emergency-login", nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled emergency route returned %d", response.Code)
		}
	}
}

func TestEmergencyAdministratorLogoutRevokesServerSession(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sessions, _ := adminauth.NewSessions("01234567890123456789012345678901", time.Hour)
	server := NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), roleDirectory{err: directory.ErrNotAuthorized}, sessions)
	server.ConfigureEmergencyAdmin(true)
	now := time.Now().UTC()
	const token = "logout-emergency-token-at-least-32-bytes"
	grant := database.EmergencyAdminGrant{ID: "logout-emergency-grant", TokenHash: emergencyTokenHash(token), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	if err = store.CreateEmergencyAdminGrantWithAudit(t.Context(), grant, ""); err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodPost, "/emergency-login", strings.NewReader(url.Values{"token": {token}}.Encode()))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(loginResponse, login)
	var cookie *http.Cookie
	for _, candidate := range loginResponse.Result().Cookies() {
		if candidate.Name == "swbadge_emergency_admin" {
			cookie = candidate
		}
	}
	if cookie == nil {
		t.Fatal("emergency login did not issue a cookie")
	}
	logout := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(url.Values{"_csrf": {sessions.CSRF(cookie.Value)}}.Encode()))
	logout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logout.AddCookie(cookie)
	logoutResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(logoutResponse, logout)
	if logoutResponse.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d", logoutResponse.Code)
	}
	reuse := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	reuse.AddCookie(cookie)
	reuseResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(reuseResponse, reuse)
	if reuseResponse.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out emergency session returned %d", reuseResponse.Code)
	}
	audits, err := store.Audits(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var revoked int
	for _, event := range audits {
		if event.EventType == "emergency_admin_grant_revoked" {
			revoked++
		}
	}
	if revoked != 1 {
		t.Fatalf("logout revoke audit count=%d", revoked)
	}
}
