package directory

import (
	"context"
	"encoding/hex"
	"errors"
	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	ldap "github.com/go-ldap/ldap/v3"
	"strings"
	"testing"
)

func creatorLDAP() LDAP {
	return LDAP{URL: "ldaps://dc.example.test:636", BaseDN: "DC=example,DC=test", CAFile: "fixture-ca.pem", UserCreatorGroupDN: "CN=Creators,DC=example,DC=test", UserCreatorGroupGUID: strings.Repeat("a", 32)}
}
func TestCreationRoleIsDirectAndPinned(t *testing.T) {
	for _, mode := range []string{"valid", "not-member", "guid", "dn", "distribution", "missing-type", "referral", "duplicate", "error"} {
		t.Run(mode, func(t *testing.T) {
			d := creatorLDAP()
			guid, _ := hex.DecodeString(d.UserCreatorGroupGUID)
			row := ldap.NewEntry(d.UserCreatorGroupDN, map[string][]string{"objectGUID": {string(guid)}, "groupType": {"-2147483646"}})
			search := &roleSearch{result: &ldap.SearchResult{Entries: []*ldap.Entry{row}}}
			switch mode {
			case "not-member":
				search.result.Entries = nil
			case "guid":
				search.result.Entries = []*ldap.Entry{ldap.NewEntry(d.UserCreatorGroupDN, map[string][]string{"objectGUID": {"wrong"}, "groupType": {"-2147483646"}})}
			case "dn":
				row.DN = "CN=Other,DC=example,DC=test"
			case "distribution":
				row = ldap.NewEntry(d.UserCreatorGroupDN, map[string][]string{"objectGUID": {string(guid)}, "groupType": {"2"}})
				search.result.Entries = []*ldap.Entry{row}
			case "missing-type":
				search.result.Entries = []*ldap.Entry{ldap.NewEntry(d.UserCreatorGroupDN, map[string][]string{"objectGUID": {string(guid)}})}
			case "referral":
				search.result.Referrals = []string{"ldaps://other.test"}
			case "duplicate":
				search.result.Entries = append(search.result.Entries, row)
			case "error":
				search.err = errors.New("offline")
			}
			roles, e := d.rolesForDN(search, "CN=Alice,DC=example,DC=test")
			if mode == "valid" {
				if e != nil || !adminauth.Allowed(adminauth.PermissionDirectoryUsersCreate, roles...) {
					t.Fatal("role missing", e)
				}
			} else if mode == "not-member" {
				if e != nil || len(roles) != 0 {
					t.Fatal("membership inferred")
				}
			} else if e == nil {
				t.Fatal("unsafe role accepted")
			}
			if search.request.Scope != ldap.ScopeBaseObject || search.request.BaseDN != d.UserCreatorGroupDN || strings.Contains(search.request.Filter, "1.2.840.113556.1.4.1941") || !strings.Contains(search.request.Filter, "(member=") {
				t.Fatal("not a direct pinned group lookup")
			}
		})
	}
}
func TestCreationSessionPrerequisites(t *testing.T) {
	if !creatorLDAP().UserCreationSessionsAllowed() {
		t.Fatal("valid fixture denied")
	}
	for _, change := range []func(*LDAP){func(d *LDAP) { d.URL = "ldap://dc.example.test" }, func(d *LDAP) { d.CertSHA256 = strings.Repeat("a", 64) }, func(d *LDAP) { d.CAFile = "" }, func(d *LDAP) { d.UserCreatorGroupGUID = "" }, func(d *LDAP) { d.UserCreatorGroupGUID = strings.Repeat("0", 32) }, func(d *LDAP) { d.UserCreatorGroupDN = "CN=Creators,DC=outside,DC=test" }, func(d *LDAP) { d.AdminGroupDN = "cn=Creators,dc=example,dc=test" }} {
		d := creatorLDAP()
		change(&d)
		if d.UserCreationSessionsAllowed() {
			t.Fatal("unsafe prerequisite accepted")
		}
	}
}
func TestReadOverlayRetainsOnlyExplicitCreationSessionAuthority(t *testing.T) {
	strict := creatorLDAP()
	lookup := func(context.Context, string) (*User, error) { return &User{Username: "read-only"}, nil }
	overlay, e := WithUserLookup(strict, lookup)
	if e != nil {
		t.Fatal(e)
	}
	authority, ok := overlay.(UserCreationSessionDirectory)
	if !ok || !authority.UserCreationSessionsAllowed() {
		t.Fatal("strict LDAP authority lost through read overlay")
	}
	local, e := WithUserLookup(Local{}, lookup)
	if e != nil {
		t.Fatal(e)
	}
	if local.(UserCreationSessionDirectory).UserCreationSessionsAllowed() {
		t.Fatal("local overlay gained AD authority")
	}
}
