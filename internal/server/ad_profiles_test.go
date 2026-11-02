package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
)

func TestADProfilesDisabledAndProtected(t *testing.T) {
	s, sessions := protectedRoleServer(t, roleDirectory{roles: []adminauth.Role{adminauth.RoleAdmin}})
	if response := roleRequest(s, sessions, "GET", "/ad-profiles"); response.Code != 403 {
		t.Fatal("default endpoint enabled")
	}
	if s.ConfigureADProfiles("relative.sock") == nil {
		t.Fatal("relative socket accepted")
	}
	if e := s.ConfigureADProfiles(filepath.Join(t.TempDir(), "executor.sock")); e != nil {
		t.Fatal(e)
	}
	token := sessions.Issue("alice", time.Now())
	for _, mode := range []string{"csrf", "origin", "http", "duplicate", "oversize", "emergency", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			form := url.Values{"_csrf": {sessions.CSRF(token)}, "action": {"read"}, "id": {strings.Repeat("1", 32)}, "password": {"synthetic"}}
			if mode == "csrf" {
				form.Set("_csrf", "wrong")
			}
			if mode == "duplicate" {
				form["action"] = []string{"read", "apply"}
			}
			if mode == "oversize" {
				form.Set("password", strings.Repeat("x", 20000))
			}
			req := httptest.NewRequest("POST", "https://identity.example/ad-profiles", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", "https://identity.example")
			req.TLS = &tls.ConnectionState{}
			if mode == "origin" {
				req.Header.Set("Origin", "https://foreign.example")
			}
			if mode == "http" {
				req.TLS = nil
			}
			if mode != "emergency" {
				req.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: token})
			}
			if mode == "mixed" {
				req.AddCookie(&http.Cookie{Name: "swbadge_emergency_admin", Value: "untrusted"})
			}
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, req)
			if response.Code == 200 {
				t.Fatal("protection bypass")
			}
			if strings.Contains(response.Body.String(), "synthetic") {
				t.Fatal("password echoed")
			}
		})
	}
	req := httptest.NewRequest("GET", "https://identity.example/ad-profiles", nil)
	req.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: token})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "Stufe 1") {
		t.Fatal("protected page missing")
	}
}
