package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
)

type administrativeRolesContextKey struct{}

func withAdministrativeRoles(ctx context.Context, roles []adminauth.Role) context.Context {
	copyOfRoles := append([]adminauth.Role(nil), roles...)
	return context.WithValue(ctx, administrativeRolesContextKey{}, copyOfRoles)
}

func administrativeRoles(ctx context.Context) []adminauth.Role {
	roles, _ := ctx.Value(administrativeRolesContextKey{}).([]adminauth.Role)
	return append([]adminauth.Role(nil), roles...)
}

func requestCan(r *http.Request, permission adminauth.Permission) bool {
	return adminauth.Allowed(permission, administrativeRoles(r.Context())...)
}

func (s *Server) currentAdministrativeRoles(ctx context.Context, username string) ([]adminauth.Role, error) {
	administrative, ok := s.dir.(directory.AdministrativeDirectory)
	if !ok {
		// Compatibility for existing non-LDAP adapters and tests. Production LDAP
		// implements AdministrativeDirectory and performs a current group lookup.
		return []adminauth.Role{adminauth.RoleAdmin}, nil
	}
	return administrative.AdministrativeRoles(ctx, username)
}

func requiredAdministrativePermission(r *http.Request) adminauth.Permission {
	path := r.URL.Path
	mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions

	switch {
	case path == "/audit":
		return adminauth.PermissionAuditRead
	case path == "/oidc-clients" || strings.HasPrefix(path, "/oidc-clients/"):
		if mutating {
			return adminauth.PermissionOIDCWrite
		}
		return adminauth.PermissionOIDCRead
	case path == "/oidc-sessions" || strings.HasPrefix(path, "/oidc-sessions/"):
		if mutating {
			return adminauth.PermissionOIDCSessionsRevoke
		}
		return adminauth.PermissionOIDCSessionsRead
	case path == "/api/v1/clients":
		return adminauth.PermissionClientsRead
	case path == "/status":
		return adminauth.PermissionSystemRead
	case path == "/pin" || strings.HasPrefix(path, "/users/") && strings.HasSuffix(path, "/pin"):
		if mutating {
			return adminauth.PermissionCredentialsWrite
		}
		return adminauth.PermissionCredentialsRead
	case path == "/badges" || strings.HasPrefix(path, "/badges/") || path == "/api/v1/badges" || strings.HasPrefix(path, "/api/v1/badges/"):
		if mutating {
			return adminauth.PermissionCredentialsWrite
		}
		return adminauth.PermissionCredentialsRead
	case path == "/users" || strings.HasPrefix(path, "/directory/users/") || path == "/api/v1/users" || strings.HasPrefix(path, "/api/v1/users/") || path == "/api/v1/directory/users":
		if mutating {
			return adminauth.PermissionIdentityWrite
		}
		return adminauth.PermissionIdentityRead
	default:
		return adminauth.PermissionDashboardRead
	}
}

func (s *Server) authorizationDenied(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, directory.ErrNotAuthorized) {
		s.problem(w, http.StatusForbidden, "authorization_required")
		return
	}
	s.log.Error("administrative role lookup failed", "component", "directory")
	s.problem(w, http.StatusServiceUnavailable, "authorization_unavailable")
}
