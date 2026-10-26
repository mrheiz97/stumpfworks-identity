package directory

import (
	"errors"
	"strings"
	"testing"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/go-ldap/ldap/v3"
)

type roleSearch struct {
	result  *ldap.SearchResult
	err     error
	request *ldap.SearchRequest
}

func (s *roleSearch) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	s.request = request
	return s.result, s.err
}

func TestRolesForDNMapsExactConfiguredRecursiveMemberships(t *testing.T) {
	d := LDAP{
		BaseDN:                  "DC=example,DC=test",
		AdminGroupDN:            "CN=Admins,DC=example,DC=test",
		OIDCOperatorGroupDN:     "CN=OIDC Operators,DC=example,DC=test",
		ClientOperatorGroupDN:   "CN=Client Operators,DC=example,DC=test",
		IdentityOperatorGroupDN: "CN=Identity Operators,DC=example,DC=test",
	}
	search := &roleSearch{result: &ldap.SearchResult{Entries: []*ldap.Entry{
		ldap.NewEntry("CN=OIDC Operators,DC=example,DC=test", map[string][]string{"distinguishedName": {"CN=OIDC Operators,DC=example,DC=test"}}),
		ldap.NewEntry("CN=Admins,DC=example,DC=test", map[string][]string{"distinguishedName": {"CN=Admins,DC=example,DC=test"}}),
		ldap.NewEntry("CN=Similarly Named Admins,DC=example,DC=test", nil),
	}}}
	roles, err := d.rolesForDN(search, "CN=Alice,OU=People,DC=example,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0] != adminauth.RoleAdmin || roles[1] != adminauth.RoleOIDCOperator {
		t.Fatalf("unexpected roles: %v", roles)
	}
	if search.request == nil || !strings.Contains(search.request.Filter, "1.2.840.113556.1.4.1941") || !strings.Contains(search.request.Filter, "CN=Alice") {
		t.Fatalf("recursive membership filter missing: %v", search.request)
	}
}

func TestRolesForDNFailsClosed(t *testing.T) {
	d := LDAP{BaseDN: "DC=example,DC=test", AdminGroupDN: "CN=Admins,DC=example,DC=test"}
	want := errors.New("directory unavailable")
	if roles, err := d.rolesForDN(&roleSearch{err: want}, "CN=Alice,DC=example,DC=test"); !errors.Is(err, want) || roles != nil {
		t.Fatalf("directory error did not fail closed: roles=%v err=%v", roles, err)
	}
	if roles, err := (LDAP{}).rolesForDN(&roleSearch{}, "CN=Alice,DC=example,DC=test"); err != nil || len(roles) != 0 {
		t.Fatalf("empty role configuration granted access: roles=%v err=%v", roles, err)
	}
}
