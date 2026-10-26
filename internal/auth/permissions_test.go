package auth

import "testing"

func TestAdministratorHasEveryPermission(t *testing.T) {
	permissions := Permissions(RoleAdmin)
	for _, permission := range allPermissions {
		if _, ok := permissions[permission]; !ok {
			t.Errorf("administrator missing %q", permission)
		}
	}
}

func TestRolePermissionBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		role       Role
		allowed    []Permission
		prohibited []Permission
	}{
		{
			name:       "identity operator",
			role:       RoleOperator,
			allowed:    []Permission{PermissionIdentityWrite, PermissionCredentialsWrite},
			prohibited: []Permission{PermissionAuditRead, PermissionOIDCWrite, PermissionClientsRead},
		},
		{
			name:       "OIDC operator",
			role:       RoleOIDCOperator,
			allowed:    []Permission{PermissionOIDCWrite, PermissionOIDCSessionsRevoke},
			prohibited: []Permission{PermissionIdentityWrite, PermissionCredentialsWrite, PermissionAuditRead},
		},
		{
			name:       "client operator",
			role:       RoleClientOperator,
			allowed:    []Permission{PermissionClientsRead, PermissionSystemRead},
			prohibited: []Permission{PermissionIdentityRead, PermissionAuditRead, PermissionOIDCRead},
		},
		{
			name:       "auditor",
			role:       RoleAuditor,
			allowed:    []Permission{PermissionAuditRead, PermissionIdentityRead, PermissionOIDCRead, PermissionClientsRead},
			prohibited: []Permission{PermissionIdentityWrite, PermissionCredentialsWrite, PermissionOIDCWrite, PermissionOIDCSessionsRevoke},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, permission := range test.allowed {
				if !Allowed(permission, test.role) {
					t.Errorf("expected %q", permission)
				}
			}
			for _, permission := range test.prohibited {
				if Allowed(permission, test.role) {
					t.Errorf("unexpected %q", permission)
				}
			}
		})
	}
}

func TestPermissionsCombineRolesAndIgnoreUnknownRole(t *testing.T) {
	roles := []Role{RoleOperator, RoleOIDCOperator, Role("unknown")}
	if !Allowed(PermissionIdentityWrite, roles...) || !Allowed(PermissionOIDCWrite, roles...) {
		t.Fatal("combined roles did not produce their permission union")
	}
	if Allowed(PermissionAuditRead, roles...) {
		t.Fatal("unknown role or role union escalated to audit access")
	}
}
