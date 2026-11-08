package directory

// Offline design spike only: no LDAP connection and no runtime write API.
import (
	"testing"

	"github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	ldap "github.com/go-ldap/ldap/v3"
)

func TestADWriteDesignScope(t *testing.T) {
	ou, err := ldap.ParseDN("OU=Managed Users,DC=example,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dn    string
		allow bool
	}{
		{"CN=Alice,OU=Managed Users,DC=example,DC=test", true},
		{`CN=Alice\, Admin,ou=managed users,dc=example,dc=test`, true},
		{"CN=Alice,OU=Nested,OU=Managed Users,DC=example,DC=test", false},
		{"CN=Alice,OU=Not Managed Users,DC=example,DC=test", false},
		{`CN=Alice\,OU=Managed Users,DC=example,DC=test`, false},
		{"OU=Managed Users,DC=example,DC=test", false},
		{"invalid", false},
	} {
		dn, parseErr := ldap.ParseDN(tc.dn)
		allowed := parseErr == nil && len(dn.RDNs) == len(ou.RDNs)+1 && (&ldap.DN{RDNs: dn.RDNs[1:]}).EqualFold(ou)
		if allowed != tc.allow {
			t.Errorf("scope %q: got %v", tc.dn, allowed)
		}
	}
}

func TestADWriteDesignNoInheritedRuntimePermission(t *testing.T) {
	roles := []auth.Role{auth.RoleAdmin, auth.RoleOperator, auth.RoleOIDCOperator, auth.RoleClientOperator, auth.RoleAuditor}
	for _, permission := range []auth.Permission{"directory.users.modify", "directory.users.create", "directory.users.disable", "directory.passwords.reset", "directory.groups.membership"} {
		if auth.Allowed(permission, roles...) {
			t.Fatalf("existing roles unexpectedly grant %s", permission)
		}
	}
}
