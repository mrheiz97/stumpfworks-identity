package adprofile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const assertionOID = "1.3.6.1.1.12"

type Directory interface {
	Ready(context.Context) error
	Authenticate(context.Context, string, string) (string, error)
	Read(context.Context, string, string) (Snapshot, error)
	Modify(context.Context, string, Snapshot, Values) error
}
type LDAP struct {
	Config   Config
	password string
	roots    *x509.CertPool
}

func NewLDAP(c Config) (*LDAP, error) {
	if c.Validate() != nil {
		return nil, ErrDenied
	}
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrDenied
	}
	p, e := os.ReadFile(c.PasswordFile)
	if e != nil || len(p) == 0 || len(p) > 1024 {
		return nil, ErrDenied
	}
	pem, e := os.ReadFile(c.CAFile)
	if e != nil {
		return nil, ErrDenied
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, ErrDenied
	}
	return &LDAP{c, strings.TrimRight(string(p), "\r\n"), roots}, nil
}
func (d *LDAP) connect(ctx context.Context) (*ldap.Conn, error) {
	if ctx.Err() != nil {
		return nil, ErrDenied
	}
	c, e := ldap.DialURL(d.Config.URL, ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.roots}), ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if e != nil {
		return nil, ErrDenied
	}
	c.SetTimeout(5 * time.Second)
	if e = c.Bind(d.Config.WriterDN, d.password); e != nil {
		c.Close()
		return nil, ErrDenied
	}
	context.AfterFunc(ctx, func() { c.Close() })
	return c, nil
}
func search(c *ldap.Conn, base string, scope int, filter string, attrs []string) ([]*ldap.Entry, error) {
	var controls []ldap.Control
	if scope == ldap.ScopeWholeSubtree {
		controls = []ldap.Control{newCriticalControl("1.2.840.113556.1.4.1339", "")}
	}
	r, e := c.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 128, 5, false, filter, attrs, controls))
	if e != nil || len(r.Referrals) > 0 || len(r.Entries) > 100 {
		return nil, ErrDenied
	}
	return r.Entries, nil
}
func one(c *ldap.Conn, base string, scope int, filter string, attrs []string) (*ldap.Entry, error) {
	r, e := search(c, base, scope, filter, attrs)
	if e != nil || len(r) != 1 {
		return nil, ErrDenied
	}
	return r[0], nil
}
func rawGUID(e *ldap.Entry) string { return hex.EncodeToString(e.GetRawAttributeValue("objectGUID")) }
func guidFilter(g string) string {
	b, _ := hex.DecodeString(g)
	var s strings.Builder
	for _, v := range b {
		fmt.Fprintf(&s, "\\%02x", v)
	}
	return "(objectGUID=" + s.String() + ")"
}
func sid(b []byte) string {
	if len(b) < 8 || len(b) != 8+4*int(b[1]) {
		return ""
	}
	authority := uint64(0)
	for _, v := range b[2:8] {
		authority = authority<<8 | uint64(v)
	}
	s := fmt.Sprintf("S-%d-%d", b[0], authority)
	for i := 8; i < len(b); i += 4 {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[i:i+4]))
	}
	return s
}
func (d *LDAP) capability(c *ldap.Conn, write bool) error {
	root, e := one(c, "", ldap.ScopeBaseObject, "(objectClass=*)", []string{"supportedControl", "defaultNamingContext", "dsServiceName"})
	if e != nil || write && !contains(root.GetAttributeValues("supportedControl"), assertionOID) {
		return ErrDenied
	}
	base, e := ldap.ParseDN(root.GetAttributeValue("defaultNamingContext"))
	want, f := ldap.ParseDN(d.Config.BaseDN)
	if e != nil || f != nil || !base.EqualFold(want) {
		return ErrDenied
	}
	domain, e := one(c, d.Config.BaseDN, ldap.ScopeBaseObject, "(objectClass=domain)", []string{"objectGUID", "objectSid"})
	if e != nil || rawGUID(domain) != d.Config.DomainGUID || sid(domain.GetRawAttributeValue("objectSid")) != d.Config.DomainSID {
		return ErrDenied
	}
	dc, e := one(c, root.GetAttributeValue("dsServiceName"), ldap.ScopeBaseObject, "(objectClass=*)", []string{"invocationId"})
	if e != nil || hex.EncodeToString(dc.GetRawAttributeValue("invocationId")) != d.Config.DCIdentity {
		return ErrDenied
	}
	return nil
}
func (d *LDAP) Authenticate(ctx context.Context, user, password string) (string, error) {
	if user == "" || len(user) > 128 || password == "" || len(password) > 1024 {
		return "", ErrDenied
	}
	c, e := d.connect(ctx)
	if e != nil {
		return "", ErrDenied
	}
	defer c.Close()
	if d.capability(c, false) != nil {
		return "", ErrDenied
	}
	actor, e := one(c, d.Config.BaseDN, ldap.ScopeWholeSubtree, "(&(objectClass=user)(!(objectClass=computer))(sAMAccountName="+ldap.EscapeFilter(user)+"))", []string{"objectSid", "userAccountControl", "memberOf"})
	if e != nil || actor.GetAttributeValue("userAccountControl") != "512" {
		return "", ErrDenied
	}
	g, e := one(c, d.Config.OperatorGroupDN, ldap.ScopeBaseObject, "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(actor.DN)+"))", []string{"objectGUID"})
	if e != nil || g == nil || rawGUID(g) != d.Config.OperatorGroupGUID {
		return "", ErrDenied
	}
	if c.Bind(actor.DN, password) != nil {
		return "", ErrDenied
	}
	identity := sid(actor.GetRawAttributeValue("objectSid"))
	if identity == "" {
		return "", ErrDenied
	}
	return identity, nil
}
func (d *LDAP) Read(ctx context.Context, guid, actor string) (Snapshot, error) {
	if !guidPattern.MatchString(guid) || !contains(d.Config.Targets, guid) || contains(d.Config.ProtectedGUIDs, guid) {
		return Snapshot{}, ErrDenied
	}
	c, e := d.connect(ctx)
	if e != nil {
		return Snapshot{}, ErrDenied
	}
	defer c.Close()
	if d.capability(c, false) != nil {
		return Snapshot{}, ErrDenied
	}
	attrs := []string{"objectGUID", "objectSid", "objectClass", "uSNChanged", "adminCount", "primaryGroupID", "userAccountControl", "servicePrincipalName", "sIDHistory", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink", "memberOf", "displayName", "givenName", "sn", "mail"}
	entry, e := one(c, d.Config.BaseDN, ldap.ScopeWholeSubtree, guidFilter(guid), attrs)
	if e != nil || !directChild(entry.DN, d.Config.ManagedOU) || !contains(entry.GetAttributeValues("objectClass"), "user") || contains(entry.GetAttributeValues("objectClass"), "computer") {
		return Snapshot{}, ErrDenied
	}
	identity := sid(entry.GetRawAttributeValue("objectSid"))
	rid, ridErr := strconv.ParseUint(identity[strings.LastIndex(identity, "-")+1:], 10, 32)
	if ridErr != nil || rid < 1000 {
		return Snapshot{}, ErrDenied
	}
	uac := entry.GetAttributeValue("userAccountControl")
	if identity == "" || identity == actor || !strings.HasPrefix(identity, d.Config.DomainSID+"-") || entry.GetAttributeValue("primaryGroupID") != "513" || (uac != "512" && uac != "514") || (entry.GetAttributeValue("adminCount") != "" && entry.GetAttributeValue("adminCount") != "0") {
		return Snapshot{}, ErrDenied
	}
	writerDN, e := ldap.ParseDN(d.Config.WriterDN)
	targetDN, f := ldap.ParseDN(entry.DN)
	if e != nil || f != nil || writerDN.EqualFold(targetDN) {
		return Snapshot{}, ErrDenied
	}
	if hasRiskValues(entry) {
		return Snapshot{}, ErrDenied
	}
	// Stage 1 permits no explicit group memberships. Reverse transitive search
	// also detects hidden/nested edges; any result (or incomplete search) denies.
	groups, e := search(c, d.Config.BaseDN, ldap.ScopeWholeSubtree, "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(entry.DN)+"))", []string{"objectSid"})
	if e != nil || len(groups) != 0 {
		return Snapshot{}, ErrDenied
	}
	if entry.GetAttributeValue("uSNChanged") == "" {
		return Snapshot{}, ErrDenied
	}
	values := Values{}
	for _, a := range []string{"displayName", "givenName", "sn", "mail"} {
		values[a] = append([]string(nil), entry.GetAttributeValues(a)...)
	}
	return Snapshot{guid, identity, entry.DN, entry.GetAttributeValue("uSNChanged"), d.Config.DCIdentity, values}, nil
}
func (d *LDAP) Modify(ctx context.Context, actor string, before Snapshot, changes Values) error {
	if validateValues(changes) != nil || before.DC != d.Config.DCIdentity {
		return ErrDenied
	}
	current, err := d.Read(ctx, before.GUID, actor)
	if err != nil || !reflect.DeepEqual(current, before) {
		return ErrDenied
	}
	c, e := d.connect(ctx)
	if e != nil {
		return ErrDenied
	}
	defer c.Close()
	if d.capability(c, true) != nil {
		return ErrDenied
	}
	// Critical assertion: unsupported controls cannot silently become unconditional writes.
	filter := "(&" + guidFilter(before.GUID) + "(uSNChanged=" + ldap.EscapeFilter(before.Version) + "))"
	encoded, e := ldap.CompileFilter(filter)
	if e != nil {
		return ErrDenied
	}
	req := ldap.NewModifyRequest(before.DN, []ldap.Control{newCriticalControl(assertionOID, string(encoded.Bytes()))})
	for a, v := range changes {
		req.Replace(a, v)
	}
	if e = c.Modify(req); e != nil {
		// Assertion/ACL/schema rejection is a definitive no-effect result. All
		// transport/protocol ambiguity is conservative and must not be replayed.
		for _, code := range []uint16{ldap.LDAPResultAssertionFailed, ldap.LDAPResultInsufficientAccessRights, ldap.LDAPResultConstraintViolation, ldap.LDAPResultNoSuchObject, ldap.LDAPResultUnavailableCriticalExtension} {
			if ldap.IsErrorWithCode(e, code) {
				return ErrDenied
			}
		}
		return ErrUncertain
	}
	return nil
}

func (d *LDAP) Ready(ctx context.Context) error {
	c, e := d.connect(ctx)
	if e != nil {
		return ErrDenied
	}
	defer c.Close()
	return d.capability(c, true)
}

func hasRiskValues(entry *ldap.Entry) bool {
	for _, attr := range []string{"servicePrincipalName", "sIDHistory", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink", "memberOf"} {
		if len(entry.GetRawAttributeValues(attr)) != 0 {
			return true
		}
	}
	return false
}
