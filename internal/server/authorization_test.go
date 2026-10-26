package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
