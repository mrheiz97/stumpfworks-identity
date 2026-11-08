package server

import (
	"context"
	"errors"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreateipc"
	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type creationSessionDirectory struct {
	roleDirectory
	allowed bool
	lookups int
}

func (d *creationSessionDirectory) UserCreationSessionsAllowed() bool { return d.allowed }
func (d *creationSessionDirectory) AdministrativeRoles(ctx context.Context, user string) ([]adminauth.Role, error) {
	d.lookups++
	return d.roleDirectory.AdministrativeRoles(ctx, user)
}

type creationBackend struct {
	enabled       bool
	calls, writes int
	user          string
}

func (b *creationBackend) IsEnabled() bool { return b.enabled }
func (b *creationBackend) Prepare(_ context.Context, user, password string, input adcreate.Input) (adcreate.Operation, error) {
	b.calls++
	b.user = user
	if user != "alice" || password != "step-up" {
		return adcreate.Operation{}, adcreate.ErrDenied
	}
	b.writes++
	return adcreate.Operation{State: "prepared", Plan: adcreate.Plan{ID: strings.Repeat("1", 32), Input: input}}, nil
}
func (b *creationBackend) Action(context.Context, string, string, string, string, string) (adcreate.Operation, error) {
	b.calls++
	return adcreate.Operation{}, adcreate.ErrDenied
}
func (b *creationBackend) History(context.Context, string, string, string) ([]adcreate.Event, error) {
	return nil, nil
}
func TestUserCreationSessionAndPermissionBoundary(t *testing.T) {
	for _, mode := range []string{"valid", "no-backend", "backend-off", "admin", "operator", "auditor", "revoked", "lookup-error", "missing", "expired", "tampered", "audience", "emergency", "mixed", "mixed-empty", "duplicate-cookie", "http", "origin", "csrf", "header-csrf", "duplicate-form", "unknown", "oversize", "bad-password"} {
		t.Run(mode, func(t *testing.T) {
			d := &creationSessionDirectory{roleDirectory: roleDirectory{roles: []adminauth.Role{adminauth.RoleUserCreator}}, allowed: true}
			s, sessions := protectedRoleServer(t, d)
			backend := &creationBackend{enabled: mode != "backend-off"}
			if mode != "no-backend" {
				if e := s.ConfigureADUserCreation(backend); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "admin":
				d.roles = []adminauth.Role{adminauth.RoleAdmin}
			case "operator":
				d.roles = []adminauth.Role{adminauth.RoleOperator}
			case "auditor":
				d.roles = []adminauth.Role{adminauth.RoleAuditor}
			case "revoked":
				d.roles = nil
			case "lookup-error":
				d.err = errors.New("synthetic lookup failure")
			}
			token := sessions.Issue("alice", time.Now())
			if mode == "expired" {
				token = sessions.Issue("alice", time.Now().Add(-2*time.Hour))
			}
			if mode == "tampered" {
				token += "x"
			}
			if mode == "audience" {
				token = sessions.IssueFor("self-service", "alice", time.Now())
			}
			form := url.Values{"_csrf": {sessions.CSRF(token)}, "action": {"prepare"}, "name": {"newuser"}, "display": {"New User"}, "password": {"step-up"}}
			switch mode {
			case "csrf":
				form.Set("_csrf", "bad")
			case "header-csrf":
				form.Del("_csrf")
			case "duplicate-form":
				form["action"] = []string{"prepare", "confirm"}
			case "unknown":
				form.Set("username", "administrator")
			case "oversize":
				form.Set("password", strings.Repeat("x", 9000))
			case "bad-password":
				form.Set("password", "wrong")
			}
			r := httptest.NewRequest("POST", "https://identity.test/ad-users/create", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "https://identity.test")
			r.Header.Set("X-CSRF-Token", sessions.CSRF(token))
			if mode == "http" {
				r.TLS = nil
			}
			if mode == "origin" {
				r.Header.Set("Origin", "https://evil.test")
			}
			if mode != "missing" && mode != "emergency" {
				r.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: token})
			}
			if mode == "duplicate-cookie" {
				r.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: token})
			}
			if mode == "mixed" || mode == "emergency" {
				r.AddCookie(&http.Cookie{Name: "swbadge_emergency_admin", Value: sessions.IssueFor("emergency-admin", "id", time.Now())})
			}
			if mode == "mixed-empty" {
				r.AddCookie(&http.Cookie{Name: "swbadge_emergency_admin", Value: ""})
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if mode == "valid" {
				if w.Code != 200 || backend.writes != 1 || backend.user != "alice" || d.lookups == 0 {
					t.Fatal("verified session not integrated", w.Code)
				}
			} else if mode == "bad-password" {
				if backend.writes != 0 || backend.calls != 1 {
					t.Fatal("step-up bypass")
				}
			} else if w.Code < 400 || backend.calls != 0 || backend.writes != 0 {
				t.Fatal("boundary bypass", w.Code, backend.calls)
			}
			if strings.Contains(w.Body.String(), "step-up") || strings.Contains(w.Body.String(), "synthetic lookup failure") {
				t.Fatal("sensitive response")
			}
		})
	}
}
func TestUserCreationHasNoLocalOrLegacyFallback(t *testing.T) {
	for _, d := range []directory.Directory{directory.Local{}, fakeDirectory{}, roleDirectory{roles: []adminauth.Role{adminauth.RoleUserCreator}}} {
		s, sessions := protectedRoleServer(t, d)
		b := &creationBackend{enabled: true}
		if s.ConfigureADUserCreation(b) == nil {
			t.Fatal("implicit adapter accepted")
		}
		// Even accidental direct attachment cannot bypass request-time boundary.
		s.creationOps = b
		r := httptest.NewRequest("GET", "https://identity.test/ad-users/create", nil)
		r.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: sessions.Issue("alice", time.Now())})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 || b.calls != 0 {
			t.Fatal("legacy session fallback")
		}
	}
	d := &creationSessionDirectory{roleDirectory: roleDirectory{roles: []adminauth.Role{adminauth.RoleUserCreator}}, allowed: true}
	s, _ := protectedRoleServer(t, d)
	s.protect = false
	if s.ConfigureADUserCreation(&creationBackend{enabled: true}) == nil {
		t.Fatal("unprotected mode enabled")
	}
}
func TestUserCreationNavigationIsOptIn(t *testing.T) {
	d := &creationSessionDirectory{roleDirectory: roleDirectory{roles: []adminauth.Role{adminauth.RoleUserCreator}}, allowed: true}
	s, _ := protectedRoleServer(t, d)
	r := httptest.NewRequest("GET", "https://identity.test/", nil)
	r = r.WithContext(withAdministrativeRoles(r.Context(), d.roles))
	if strings.Contains(s.compactAdminSidebar(r, "/"), "/ad-users/create") {
		t.Fatal("default menu enabled")
	}
	b := &creationBackend{enabled: true}
	if s.ConfigureADUserCreation(b) != nil {
		t.Fatal("configure")
	}
	if !strings.Contains(s.compactAdminSidebar(r, "/"), "/ad-users/create") {
		t.Fatal("creator menu missing")
	}
	r = r.WithContext(withAdministrativeRoles(r.Context(), []adminauth.Role{adminauth.RoleAdmin}))
	if strings.Contains(s.compactAdminSidebar(r, "/"), "/ad-users/create") {
		t.Fatal("admin inherited creation menu")
	}
	s.ConfigureADUserCreation(nil)
	if s.creationOps != nil {
		t.Fatal("disable")
	}
}
func TestUserCreationRechecksRoleForExistingSession(t *testing.T) {
	d := &creationSessionDirectory{roleDirectory: roleDirectory{roles: []adminauth.Role{adminauth.RoleUserCreator}}, allowed: true}
	s, sessions := protectedRoleServer(t, d)
	s.ConfigureADUserCreation(&creationBackend{enabled: true})
	token := sessions.Issue("alice", time.Now())
	check := func() int {
		r := httptest.NewRequest("GET", "https://identity.test/ad-users/create", nil)
		r.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: token})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if check() != 200 {
		t.Fatal("valid session")
	}
	d.roles = nil
	if check() != 403 || d.lookups != 2 {
		t.Fatal("cached permission survived revocation")
	}
}
func TestCreationTransportDefaultAndInvalidPinsStayDisabled(t *testing.T) {
	d := &creationSessionDirectory{roleDirectory: roleDirectory{roles: []adminauth.Role{adminauth.RoleUserCreator}}, allowed: true}
	s, _ := protectedRoleServer(t, d)
	if e := s.ConfigureADUserCreationTransport(adcreateipc.Config{}); e != nil || s.creationOps != nil {
		t.Fatal("default transport attached")
	}
	if e := s.ConfigureADUserCreationTransport(adcreateipc.Config{Enabled: true, Socket: "/untrusted/endpoint"}); e == nil || s.creationOps != nil {
		t.Fatal("unidentified peer attached")
	}
}
