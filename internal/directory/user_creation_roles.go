package directory

import (
	"encoding/hex"
	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	ldap "github.com/go-ldap/ldap/v3"
	"net/url"
	"strconv"
	"strings"
)

func (d LDAP) UserCreationSessionsAllowed() bool {
	u, e := url.Parse(d.URL)
	if e != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" || u.Fragment != "" || d.CAFile == "" || d.CertSHA256 != "" {
		return false
	}
	guid, e := hex.DecodeString(d.UserCreatorGroupGUID)
	if e != nil || len(guid) != 16 || d.UserCreatorGroupGUID == strings.Repeat("0", 32) {
		return false
	}
	group, e := ldap.ParseDN(d.UserCreatorGroupDN)
	if e != nil {
		return false
	}
	base, e := ldap.ParseDN(d.BaseDN)
	if e != nil || len(base.RDNs) == 0 || len(group.RDNs) <= len(base.RDNs) || !(&ldap.DN{RDNs: group.RDNs[len(group.RDNs)-len(base.RDNs):]}).EqualFold(base) {
		return false
	}
	for _, other := range []string{d.AdminGroupDN, d.IdentityOperatorGroupDN, d.OIDCOperatorGroupDN, d.ClientOperatorGroupDN, d.AuditorGroupDN} {
		if other == "" {
			continue
		}
		dn, e := ldap.ParseDN(other)
		if e != nil || dn.EqualFold(group) {
			return false
		}
	}
	return true
}
func (d LDAP) rolesForDN(searcher ldapSearcher, userDN string) ([]adminauth.Role, error) {
	roles, e := d.legacyRolesForDN(searcher, userDN)
	if e != nil {
		return nil, e
	}
	if d.UserCreatorGroupDN == "" && d.UserCreatorGroupGUID == "" {
		return roles, nil
	}
	if !d.UserCreationSessionsAllowed() {
		return nil, ErrNotAuthorized
	}
	result, e := searcher.Search(ldap.NewSearchRequest(d.UserCreatorGroupDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false,
		"(&(objectClass=group)(member="+ldap.EscapeFilter(userDN)+"))", []string{"objectGUID", "groupType"}, nil))
	if e != nil {
		return nil, e
	}
	if result == nil || len(result.Referrals) > 0 || len(result.Entries) > 1 {
		return nil, ErrNotAuthorized
	}
	if len(result.Entries) == 0 {
		return roles, nil
	}
	row := result.Entries[0]
	if row == nil || len(row.GetAttributeValues("groupType")) != 1 {
		return nil, ErrNotAuthorized
	}
	wanted, _ := ldap.ParseDN(d.UserCreatorGroupDN)
	actual, e := ldap.ParseDN(row.DN)
	values := row.GetRawAttributeValues("objectGUID")
	groupType, typeErr := strconv.ParseInt(row.GetAttributeValue("groupType"), 10, 64)
	if e != nil || typeErr != nil || groupType < -2147483648 || groupType > 4294967295 || uint32(groupType)&0x80000000 == 0 || !actual.EqualFold(wanted) || len(values) != 1 || len(values[0]) != 16 || !strings.EqualFold(hex.EncodeToString(values[0]), d.UserCreatorGroupGUID) {
		return nil, ErrNotAuthorized
	}
	return append(roles, adminauth.RoleUserCreator), nil
}
