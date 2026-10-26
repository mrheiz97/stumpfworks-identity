package auth

// Role is an Identity-local administrative role. Roles are derived from the
// current directory memberships and are deliberately not OIDC claims.
type Role string

const (
	RoleAdmin          Role = "identity-admin"
	RoleOperator       Role = "identity-operator"
	RoleOIDCOperator   Role = "oidc-operator"
	RoleClientOperator Role = "client-operator"
	RoleAuditor        Role = "identity-auditor"
)

// Permission identifies one server-side administrative capability.
type Permission string

const (
	PermissionDashboardRead      Permission = "dashboard.read"
	PermissionIdentityRead       Permission = "identity.read"
	PermissionIdentityWrite      Permission = "identity.write"
	PermissionCredentialsRead    Permission = "credentials.read"
	PermissionCredentialsWrite   Permission = "credentials.write"
	PermissionAuditRead          Permission = "audit.read"
	PermissionOIDCRead           Permission = "oidc.read"
	PermissionOIDCWrite          Permission = "oidc.write"
	PermissionOIDCSessionsRead   Permission = "oidc.sessions.read"
	PermissionOIDCSessionsRevoke Permission = "oidc.sessions.revoke"
	PermissionClientsRead        Permission = "clients.read"
	PermissionSystemRead         Permission = "system.read"
)

var allPermissions = []Permission{
	PermissionDashboardRead,
	PermissionIdentityRead,
	PermissionIdentityWrite,
	PermissionCredentialsRead,
	PermissionCredentialsWrite,
	PermissionAuditRead,
	PermissionOIDCRead,
	PermissionOIDCWrite,
	PermissionOIDCSessionsRead,
	PermissionOIDCSessionsRevoke,
	PermissionClientsRead,
	PermissionSystemRead,
}

var rolePermissions = map[Role][]Permission{
	RoleAdmin: allPermissions,
	RoleOperator: {
		PermissionDashboardRead,
		PermissionIdentityRead,
		PermissionIdentityWrite,
		PermissionCredentialsRead,
		PermissionCredentialsWrite,
		PermissionSystemRead,
	},
	RoleOIDCOperator: {
		PermissionDashboardRead,
		PermissionOIDCRead,
		PermissionOIDCWrite,
		PermissionOIDCSessionsRead,
		PermissionOIDCSessionsRevoke,
		PermissionSystemRead,
	},
	RoleClientOperator: {
		PermissionDashboardRead,
		PermissionClientsRead,
		PermissionSystemRead,
	},
	RoleAuditor: {
		PermissionDashboardRead,
		PermissionIdentityRead,
		PermissionCredentialsRead,
		PermissionAuditRead,
		PermissionOIDCRead,
		PermissionOIDCSessionsRead,
		PermissionClientsRead,
		PermissionSystemRead,
	},
}

// Permissions returns a newly allocated permission set for the union of roles.
// Unknown roles grant nothing.
func Permissions(roles ...Role) map[Permission]struct{} {
	permissions := make(map[Permission]struct{})
	for _, role := range roles {
		for _, permission := range rolePermissions[role] {
			permissions[permission] = struct{}{}
		}
	}
	return permissions
}

// Allowed reports whether the supplied roles grant permission.
func Allowed(permission Permission, roles ...Role) bool {
	_, ok := Permissions(roles...)[permission]
	return ok
}
