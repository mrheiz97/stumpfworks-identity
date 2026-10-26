package directory

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/go-ldap/ldap/v3"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrNotAuthorized      = errors.New("not authorized")
	ErrUserNotFound       = errors.New("directory user not found")
)

type LDAP struct {
	URL, BaseDN, BindDN, BindPassword, Domain, AdminGroupDN, CAFile, CertSHA256 string
	IdentityOperatorGroupDN, OIDCOperatorGroupDN                                string
	ClientOperatorGroupDN, AuditorGroupDN                                       string
}

type ldapSearcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func (d LDAP) connect(ctx context.Context) (*ldap.Conn, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if d.CAFile != "" {
		pem, err := os.ReadFile(d.CAFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("directory CA file contains no certificates")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	if d.CertSHA256 != "" {
		expected, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(d.CertSHA256), ":", ""))
		if err != nil || len(expected) != sha256.Size {
			return nil, errors.New("invalid directory certificate SHA-256 pin")
		}
		tlsConfig.InsecureSkipVerify = true // Exact pin below compensates for the legacy Samba certificate's missing SAN.
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("directory returned no certificate")
			}
			actual := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !hmac.Equal(actual[:], expected) {
				return errors.New("directory certificate pin mismatch")
			}
			return nil
		}
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	c, err := ldap.DialURL(d.URL, ldap.DialWithTLSConfig(tlsConfig), ldap.DialWithDialer(dialer))
	if err != nil {
		return nil, err
	}
	c.SetTimeout(8 * time.Second)
	select {
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	default:
		return c, nil
	}
}
func (d LDAP) serviceConn(ctx context.Context) (*ldap.Conn, error) {
	c, e := d.connect(ctx)
	if e != nil {
		return nil, e
	}
	if e = c.Bind(d.BindDN, d.BindPassword); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
func (d LDAP) userFilter(u string) string {
	return fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName=%s))", ldap.EscapeFilter(u))
}
func userFromEntry(e *ldap.Entry) User {
	display := e.GetAttributeValue("displayName")
	if display == "" {
		display = e.GetAttributeValue("sAMAccountName")
	}
	return User{Username: e.GetAttributeValue("sAMAccountName"), DisplayName: display, DN: e.DN, Mail: e.GetAttributeValue("mail")}
}
func (d LDAP) searchOne(c *ldap.Conn, u string) (*User, error) {
	r, e := c.Search(ldap.NewSearchRequest(d.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 8, false, d.userFilter(u), []string{"sAMAccountName", "displayName", "mail"}, nil))
	if e != nil {
		return nil, e
	}
	if len(r.Entries) != 1 {
		return nil, ErrUserNotFound
	}
	x := userFromEntry(r.Entries[0])
	return &x, nil
}
func (d LDAP) GetUser(ctx context.Context, u string) (*User, error) {
	c, e := d.serviceConn(ctx)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	return d.searchOne(c, u)
}
func (d LDAP) UserExists(ctx context.Context, u string) (bool, error) {
	_, e := d.GetUser(ctx, u)
	if errors.Is(e, ErrUserNotFound) {
		return false, nil
	}
	return e == nil, e
}
func (d LDAP) ListUsers(ctx context.Context) ([]User, error) {
	c, e := d.serviceConn(ctx)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	filter := "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	r, e := c.Search(ldap.NewSearchRequest(d.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1000, 10, false, filter, []string{"sAMAccountName", "displayName", "mail"}, nil))
	if e != nil {
		return nil, e
	}
	out := make([]User, 0, len(r.Entries))
	for _, entry := range r.Entries {
		u := userFromEntry(entry)
		if u.Username != "" && !strings.HasSuffix(u.Username, "$") {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].DisplayName) < strings.ToLower(out[j].DisplayName) })
	return out, nil
}
func (d LDAP) AuthenticateAdmin(ctx context.Context, username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	service, e := d.serviceConn(ctx)
	if e != nil {
		return nil, e
	}
	u, e := d.searchOne(service, username)
	if e != nil {
		service.Close()
		return nil, ErrInvalidCredentials
	}
	roles, e := d.rolesForDN(service, u.DN)
	service.Close()
	if e != nil {
		return nil, e
	}
	if !hasRole(roles, adminauth.RoleAdmin) {
		return nil, ErrNotAuthorized
	}
	return d.authenticateUser(ctx, u, username, password)
}

// AdministrativeRoles resolves the user's current recursive role memberships
// over a service-bound connection. It does not authenticate a password.
func (d LDAP) AdministrativeRoles(ctx context.Context, username string) ([]adminauth.Role, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrNotAuthorized
	}
	service, err := d.serviceConn(ctx)
	if err != nil {
		return nil, err
	}
	defer service.Close()
	u, err := d.searchOne(service, username)
	if err != nil {
		return nil, ErrNotAuthorized
	}
	roles, err := d.rolesForDN(service, u.DN)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, ErrNotAuthorized
	}
	return roles, nil
}

// AuthenticateAdministrative accepts a user belonging to any configured
// administrative role. The legacy AuthenticateAdmin method remains restricted
// to the full administrator group.
func (d LDAP) AuthenticateAdministrative(ctx context.Context, username, password string) (*User, []adminauth.Role, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, nil, ErrInvalidCredentials
	}
	service, err := d.serviceConn(ctx)
	if err != nil {
		return nil, nil, err
	}
	u, err := d.searchOne(service, username)
	if err != nil {
		service.Close()
		return nil, nil, ErrInvalidCredentials
	}
	roles, err := d.rolesForDN(service, u.DN)
	service.Close()
	if err != nil {
		return nil, nil, err
	}
	if len(roles) == 0 {
		return nil, nil, ErrNotAuthorized
	}
	u, err = d.authenticateUser(ctx, u, username, password)
	if err != nil {
		return nil, nil, err
	}
	return u, roles, nil
}

func (d LDAP) rolesForDN(searcher ldapSearcher, userDN string) ([]adminauth.Role, error) {
	groups := []struct {
		role adminauth.Role
		dn   string
	}{
		{adminauth.RoleAdmin, d.AdminGroupDN},
		{adminauth.RoleOperator, d.IdentityOperatorGroupDN},
		{adminauth.RoleOIDCOperator, d.OIDCOperatorGroupDN},
		{adminauth.RoleClientOperator, d.ClientOperatorGroupDN},
		{adminauth.RoleAuditor, d.AuditorGroupDN},
	}
	dnRoles := make(map[string]adminauth.Role)
	filters := make([]string, 0, len(groups))
	for _, group := range groups {
		dn := strings.TrimSpace(group.dn)
		if dn == "" {
			continue
		}
		dnRoles[strings.ToLower(dn)] = group.role
		filters = append(filters, "(distinguishedName="+ldap.EscapeFilter(dn)+")")
	}
	if len(filters) == 0 {
		return nil, nil
	}
	filter := fmt.Sprintf("(&(|%s)(member:1.2.840.113556.1.4.1941:=%s))", strings.Join(filters, ""), ldap.EscapeFilter(userDN))
	result, err := searcher.Search(ldap.NewSearchRequest(d.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, len(filters), 8, false, filter, []string{"distinguishedName"}, nil))
	if err != nil {
		return nil, err
	}
	found := make(map[adminauth.Role]struct{})
	for _, entry := range result.Entries {
		dn := entry.GetAttributeValue("distinguishedName")
		if dn == "" {
			dn = entry.DN
		}
		if role, ok := dnRoles[strings.ToLower(strings.TrimSpace(dn))]; ok {
			found[role] = struct{}{}
		}
	}
	roles := make([]adminauth.Role, 0, len(found))
	for _, group := range groups {
		if _, ok := found[group.role]; ok {
			roles = append(roles, group.role)
		}
	}
	return roles, nil
}

func hasRole(roles []adminauth.Role, wanted adminauth.Role) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}
func (d LDAP) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	service, e := d.serviceConn(ctx)
	if e != nil {
		return nil, e
	}
	u, e := d.searchOne(service, username)
	service.Close()
	if e != nil {
		return nil, ErrInvalidCredentials
	}
	return d.authenticateUser(ctx, u, username, password)
}
func (d LDAP) authenticateUser(ctx context.Context, u *User, username, password string) (*User, error) {
	login, e := d.connect(ctx)
	if e != nil {
		return nil, e
	}
	defer login.Close()
	principal := username
	if !strings.ContainsAny(principal, "@\\") {
		principal += "@" + d.Domain
	}
	if e = login.Bind(principal, password); e != nil {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}
