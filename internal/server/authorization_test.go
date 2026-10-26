package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
)

type roleDirectory struct {
	fakeDirectory
	roles []adminauth.Role
	err   error
}

func (d roleDirectory) AdministrativeRoles(context.Context, string) ([]adminauth.Role, error) {
	return append([]adminauth.Role(nil), d.roles...), d.err
}

func (d roleDirectory) AuthenticateAdministrative(_ context.Context, username, password string) (*directory.User, []adminauth.Role, error) {
	if password != "correct" || d.err != nil || len(d.roles) == 0 {
		if d.err != nil {
			return nil, nil, d.err
		}
		return nil, nil, directory.ErrNotAuthorized
	}
	return &directory.User{Username: username}, append([]adminauth.Role(nil), d.roles...), nil
}

func protectedRoleServer(t *testing.T, d directory.Directory) (*Server, *adminauth.Sessions) {
	t.Helper()
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sessions, err := adminauth.NewSessions("01234567890123456789012345678901", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), d, sessions), sessions
}

func roleRequest(server *Server, sessions *adminauth.Sessions, method, path string) *httptest.ResponseRecorder {
	token := sessions.Issue("alice", time.Now())
	request := httptest.NewRequest(method, path, nil)
	request.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: token})
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		request.Header.Set("X-CSRF-Token", sessions.CSRF(token))
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func TestAdministrativeRoutesEnforceCurrentRolePermissions(t *testing.T) {
	tests := []struct {
		name    string
		role    adminauth.Role
		allowed []string
		denied  []string
	}{
		{"identity operator", adminauth.RoleOperator, []string{"/users", "/badges", "/pin"}, []string{"/audit", "/oidc-clients", "/api/v1/clients"}},
		{"OIDC operator", adminauth.RoleOIDCOperator, []string{"/oidc-clients", "/oidc-sessions"}, []string{"/users", "/badges", "/audit"}},
		{"client operator", adminauth.RoleClientOperator, []string{"/status", "/api/v1/clients"}, []string{"/users", "/badges", "/oidc-clients", "/audit"}},
		{"auditor", adminauth.RoleAuditor, []string{"/users", "/badges", "/audit", "/oidc-clients", "/oidc-sessions", "/api/v1/clients"}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, sessions := protectedRoleServer(t, roleDirectory{roles: []adminauth.Role{test.role}})
			for _, path := range test.allowed {
				if response := roleRequest(server, sessions, http.MethodGet, path); response.Code == http.StatusForbidden || response.Code == http.StatusUnauthorized {
					t.Errorf("GET %s was denied with %d", path, response.Code)
				}
			}
			for _, path := range test.denied {
				if response := roleRequest(server, sessions, http.MethodGet, path); response.Code != http.StatusForbidden {
					t.Errorf("GET %s returned %d, want 403", path, response.Code)
				}
			}
		})
	}
}

func TestAuditorCannotMutateDirectRoutes(t *testing.T) {
	server, sessions := protectedRoleServer(t, roleDirectory{roles: []adminauth.Role{adminauth.RoleAuditor}})
	for _, path := range []string{"/users", "/badges", "/directory/users/import", "/users/1/pin", "/oidc-clients", "/oidc-sessions/session/revoke"} {
		if response := roleRequest(server, sessions, http.MethodPost, path); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "authorization_required") {
			t.Errorf("POST %s returned %d %q, want authorization denial", path, response.Code, response.Body.String())
		}
	}
}

func TestAdministrativeRoleRemovalAndDirectoryFailureFailClosed(t *testing.T) {
	server, sessions := protectedRoleServer(t, roleDirectory{err: directory.ErrNotAuthorized})
	if response := roleRequest(server, sessions, http.MethodGet, "/"); response.Code != http.StatusForbidden {
		t.Fatalf("removed role returned %d", response.Code)
	}
	server, sessions = protectedRoleServer(t, roleDirectory{err: errors.New("directory unavailable")})
	if response := roleRequest(server, sessions, http.MethodGet, "/"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("directory failure returned %d", response.Code)
	}
	if response := roleRequest(server, sessions, http.MethodPost, "/logout"); response.Code != http.StatusSeeOther {
		t.Fatalf("directory failure prevented logout: %d", response.Code)
	}
}

func TestLegacyAdministratorAdapterRetainsFullAccess(t *testing.T) {
	server, sessions := protectedRoleServer(t, fakeDirectory{})
	for _, path := range []string{"/", "/users", "/badges", "/audit", "/oidc-clients", "/oidc-sessions", "/status", "/api/v1/clients"} {
		if response := roleRequest(server, sessions, http.MethodGet, path); response.Code == http.StatusForbidden || response.Code == http.StatusUnauthorized {
			t.Errorf("legacy administrator GET %s was denied with %d", path, response.Code)
		}
	}
}

func TestAdministrativePagesHideUnavailableNavigationAndActions(t *testing.T) {
	operatorServer, operatorSessions := protectedRoleServer(t, roleDirectory{roles: []adminauth.Role{adminauth.RoleOperator}})
	operatorDashboard := roleRequest(operatorServer, operatorSessions, http.MethodGet, "/").Body.String()
	for _, visible := range []string{"Users", "Badges", "System status"} {
		if !strings.Contains(operatorDashboard, visible) {
			t.Errorf("operator navigation is missing %q", visible)
		}
	}
	for _, hidden := range []string{"Audit log", "OIDC clients", "OIDC sessions"} {
		if strings.Contains(operatorDashboard, hidden) {
			t.Errorf("operator navigation exposed %q", hidden)
		}
	}

	auditorServer, auditorSessions := protectedRoleServer(t, roleDirectory{roles: []adminauth.Role{adminauth.RoleAuditor}})
	usersPage := roleRequest(auditorServer, auditorSessions, http.MethodGet, "/users").Body.String()
	if strings.Contains(usersPage, `action="/directory/users/import"`) || strings.Contains(usersPage, "Manage PINs") {
		t.Fatal("auditor user page rendered mutation controls")
	}
	badgesPage := roleRequest(auditorServer, auditorSessions, http.MethodGet, "/badges").Body.String()
	if strings.Contains(badgesPage, "Issue a new badge") || strings.Contains(badgesPage, `action="/badges"`) {
		t.Fatal("auditor badge page rendered mutation controls")
	}
	oidcPage := roleRequest(auditorServer, auditorSessions, http.MethodGet, "/oidc-clients").Body.String()
	if !strings.Contains(oidcPage, "Read-only view") || strings.Contains(oidcPage, "Register client") || strings.Contains(oidcPage, "Rotate secret") {
		t.Fatal("auditor OIDC page was not read-only")
	}

	oidcServer, oidcSessions := protectedRoleServer(t, roleDirectory{roles: []adminauth.Role{adminauth.RoleOIDCOperator}})
	if body := roleRequest(oidcServer, oidcSessions, http.MethodGet, "/oidc-clients").Body.String(); !strings.Contains(body, "Register client") {
		t.Fatal("OIDC operator mutation controls are missing")
	}
}

func TestAdministrativeRoutePermissionMatrix(t *testing.T) {
	tests := []struct {
		method     string
		path       string
		permission adminauth.Permission
	}{
		{http.MethodGet, "/", adminauth.PermissionDashboardRead},
		{http.MethodGet, "/users", adminauth.PermissionIdentityRead},
		{http.MethodPost, "/users", adminauth.PermissionIdentityWrite},
		{http.MethodGet, "/api/v1/users/1", adminauth.PermissionIdentityRead},
		{http.MethodPost, "/directory/users/import", adminauth.PermissionIdentityWrite},
		{http.MethodGet, "/badges", adminauth.PermissionCredentialsRead},
		{http.MethodPost, "/badges/1/revoke", adminauth.PermissionCredentialsWrite},
		{http.MethodGet, "/api/v1/badges/1/qr", adminauth.PermissionCredentialsRead},
		{http.MethodGet, "/pin", adminauth.PermissionCredentialsRead},
		{http.MethodPost, "/users/1/pin", adminauth.PermissionCredentialsWrite},
		{http.MethodGet, "/audit", adminauth.PermissionAuditRead},
		{http.MethodGet, "/oidc-clients", adminauth.PermissionOIDCRead},
		{http.MethodPost, "/oidc-clients/client/rotate-secret", adminauth.PermissionOIDCWrite},
		{http.MethodGet, "/oidc-sessions", adminauth.PermissionOIDCSessionsRead},
		{http.MethodPost, "/oidc-sessions/session/revoke", adminauth.PermissionOIDCSessionsRevoke},
		{http.MethodGet, "/api/v1/clients", adminauth.PermissionClientsRead},
		{http.MethodGet, "/status", adminauth.PermissionSystemRead},
	}
	for _, test := range tests {
		request := httptest.NewRequest(test.method, test.path, nil)
		if got := requiredAdministrativePermission(request); got != test.permission {
			t.Errorf("%s %s requires %q, want %q", test.method, test.path, got, test.permission)
		}
	}
}

func TestLimitedRoleLoginIssuesIdentityOnlySessionAndAudit(t *testing.T) {
	server, sessions := protectedRoleServer(t, roleDirectory{roles: []adminauth.Role{adminauth.RoleAuditor}})
	form := strings.NewReader("username=alice&password=correct")
	request := httptest.NewRequest(http.MethodPost, "/login", form)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || len(response.Result().Cookies()) != 1 {
		t.Fatalf("limited role login returned %d with %d cookies", response.Code, len(response.Result().Cookies()))
	}
	cookie := response.Result().Cookies()[0]
	username, err := sessions.Verify(cookie.Value, time.Now())
	if err != nil || username != "alice" {
		t.Fatalf("issued session is invalid: %q %v", username, err)
	}
	for _, role := range []adminauth.Role{adminauth.RoleAdmin, adminauth.RoleAuditor} {
		if strings.Contains(cookie.Value, string(role)) {
			t.Fatal("session exposed an administrative role")
		}
	}
	audits, err := server.store.Audits(t.Context())
	if err != nil || len(audits) != 1 || audits[0].EventType != "admin_login" || audits[0].Username != "alice" {
		t.Fatalf("limited role login audit missing: %+v %v", audits, err)
	}
}

type changingRoleDirectory struct {
	fakeDirectory
	mu    sync.RWMutex
	roles []adminauth.Role
}

func (d *changingRoleDirectory) AdministrativeRoles(context.Context, string) ([]adminauth.Role, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.roles) == 0 {
		return nil, directory.ErrNotAuthorized
	}
	return append([]adminauth.Role(nil), d.roles...), nil
}

func (d *changingRoleDirectory) AuthenticateAdministrative(_ context.Context, username, _ string) (*directory.User, []adminauth.Role, error) {
	roles, err := d.AdministrativeRoles(context.Background(), username)
	if err != nil {
		return nil, nil, err
	}
	return &directory.User{Username: username}, roles, nil
}

func TestAdministrativeRoleRemovalIsNotCached(t *testing.T) {
	d := &changingRoleDirectory{roles: []adminauth.Role{adminauth.RoleAdmin}}
	server, sessions := protectedRoleServer(t, d)
	if response := roleRequest(server, sessions, http.MethodGet, "/audit"); response.Code != http.StatusOK {
		t.Fatalf("administrator was denied before removal: %d", response.Code)
	}
	d.mu.Lock()
	d.roles = nil
	d.mu.Unlock()
	for i := 0; i < 16; i++ {
		if response := roleRequest(server, sessions, http.MethodGet, "/audit"); response.Code != http.StatusForbidden {
			t.Fatalf("request %d after role removal returned %d", i, response.Code)
		}
	}
}
