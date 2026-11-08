package adprofile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	ldap "github.com/go-ldap/ldap/v3"
)

type CreatePins struct {
	ActorGUID      string
	ActorSID       string
	WriterGUID     string
	ReceiptPublic  string
	Scope          string
	Epoch          uint64 `json:",omitempty"`
	FixedUPNSuffix string `json:",omitempty"`
}

// NewNativeCreate binds the native Create protocol to the synthetic lab domain.
// The profile LDAP Ready and Modify paths retain their own capability checks.
func NewNativeCreate(c Config, p CreatePins, ou string, key ed25519.PrivateKey) (*NativeCreate, adcreate.Scope, error) {
	scope := adcreate.Scope{Domain: c.DomainGUID, DC: c.DCIdentity, OU: ou, Policy: c.Revision, UPNSuffix: "profile.test", Epoch: p.Epoch}
	labURL := c.URL == "ldaps://dc1.profile.test:636"
	if p.Epoch != 0 {
		scope.UPNSuffix = "managed.profile.test"
		labURL = labURL || c.URL == "ldaps://dc2.profile.test:636"
	}
	if p.FixedUPNSuffix != "" {
		endpoint, err := url.Parse(c.URL)
		if err != nil || p.Epoch == 0 || !fixedDNSName.MatchString(p.FixedUPNSuffix) ||
			!fixedDNSName.MatchString(endpoint.Hostname()) || endpoint.Port() != "636" ||
			c.URL != "ldaps://"+endpoint.Hostname()+":636" {
			return nil, scope, ErrDenied
		}
		scope.UPNSuffix = p.FixedUPNSuffix
		labURL = true
	}
	raw, e := hex.DecodeString(p.ActorSID)
	for _, v := range []string{ou, p.ActorGUID, p.WriterGUID} {
		if !guidPattern.MatchString(v) || v == strings.Repeat("0", 32) {
			return nil, scope, ErrDenied
		}
	}
	for _, v := range []string{p.ReceiptPublic, p.Scope} {
		b, e := hex.DecodeString(v)
		if e != nil || len(b) != 32 || bytes.Equal(b, make([]byte, 32)) {
			return nil, scope, ErrDenied
		}
	}
	if e != nil || !strings.HasPrefix(sid(raw), c.DomainSID+"-") || len(key) != ed25519.PrivateKeySize || !labURL ||
		(p.FixedUPNSuffix == "" && !strings.EqualFold(c.BaseDN, "DC=profile,DC=test")) {
		return nil, scope, ErrDenied
	}
	if !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) {
		return nil, scope, ErrDenied
	}
	if strings.EqualFold(p.ReceiptPublic, hex.EncodeToString(key.Public().(ed25519.PublicKey))) {
		return nil, scope, ErrDenied
	}
	if p.FixedUPNSuffix == "" {
		interfaces, err := net.Interfaces()
		if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
			return nil, scope, ErrDenied
		}
	}
	l, e := NewLDAP(c)
	if e != nil {
		return nil, scope, e
	}
	return &NativeCreate{ldap: l, pins: p, scope: scope, private: append(ed25519.PrivateKey(nil), key...)}, scope, nil
}

var createName = regexp.MustCompile("^[a-z][a-z0-9._-]{0,19}$")
var fixedDNSName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
var createDigest = regexp.MustCompile("^[0-9a-f]{64}$")

func (d *NativeCreate) policyHash(policy string) [32]byte {
	if d.pins.FixedUPNSuffix != "" {
		policy += "\x00" + d.pins.FixedUPNSuffix
	}
	return sha256.Sum256([]byte(policy))
}

func (d *NativeCreate) validPlan(p adcreate.Plan) bool {
	if p.Scope != d.scope || !idPattern.MatchString(p.ID) || p.ID == strings.Repeat("0", 32) || !createDigest.MatchString(p.Digest) || p.Expires <= 0 || !createName.MatchString(p.Input.Name) || len(p.Input.DisplayName) == 0 || len(p.Input.DisplayName) > 256 {
		return false
	}
	for _, b := range []byte(p.Input.DisplayName) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
func (d *NativeCreate) Authenticate(ctx context.Context, user, password string) (string, error) {
	return d.ldap.Authenticate(ctx, user, password)
}
func (d *NativeCreate) Ready(ctx context.Context) error {
	c, e := d.ldap.connect(ctx)
	if e != nil {
		return ErrDenied
	}
	defer c.Close()
	if d.ldap.capability(c, false) != nil {
		return ErrDenied
	}
	ou, e := one(c, d.ldap.Config.ManagedOU, ldap.ScopeBaseObject, "(objectClass=organizationalUnit)", []string{"objectGUID"})
	if e != nil || rawGUID(ou) != d.scope.OU {
		return ErrDenied
	}
	writer, e := one(c, d.ldap.Config.WriterDN, ldap.ScopeBaseObject, "(objectClass=user)", []string{"objectGUID"})
	if e != nil || rawGUID(writer) != d.pins.WriterGUID {
		return ErrDenied
	}
	// The status query binds a random operation ID and has no Add side effect.
	frame := make([]byte, 264)
	if _, e = rand.Read(frame[8:24]); e != nil {
		return ErrDenied
	}
	raw, q, e := d.query(ctx, adcreate.Plan{Scope: d.scope}, frame)
	pub, _ := hex.DecodeString(d.pins.ReceiptPublic)
	if e != nil || !validCreateReceipt(raw, q, pub, time.Now().Unix()) || raw[256] != 0 || !bytes.Equal(raw[257:350], make([]byte, 93)) {
		return ErrDenied
	}
	return nil
}

type NativeCreate struct {
	ldap    *LDAP
	private ed25519.PrivateKey
	pins    CreatePins
	scope   adcreate.Scope
}

func (d *NativeCreate) Available(ctx context.Context, scope adcreate.Scope, input adcreate.Input) error {
	if scope != d.scope {
		return ErrDenied
	}
	c, e := d.ldap.connect(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	rows, e := search(c, d.ldap.Config.BaseDN, ldap.ScopeWholeSubtree, "(|(sAMAccountName="+ldap.EscapeFilter(input.Name)+")(userPrincipalName="+ldap.EscapeFilter(input.Name+"@"+scope.UPNSuffix)+"))", []string{"objectGUID"})
	if e != nil || len(rows) != 0 {
		return ErrDenied
	}
	return nil
}
func (d *NativeCreate) frame(p adcreate.Plan) []byte {
	now := time.Now().Unix()
	end := now + 60
	if p.Expires < end {
		end = p.Expires
	}
	body := d.body(p, now, end)
	return append(body, ed25519.Sign(d.private, body)...)
}
func (d *NativeCreate) body(p adcreate.Plan, issued, expires int64) []byte {
	body := []byte("SWNEW001")
	if p.Scope.Epoch != 0 {
		body = []byte("SWNEW002")
	}
	for _, value := range []string{p.ID, p.Scope.Domain, p.Scope.DC, p.Scope.OU, d.pins.ActorGUID, d.pins.WriterGUID, d.ldap.Config.OperatorGroupGUID} {
		b, _ := hex.DecodeString(value)
		body = append(body, b...)
	}
	body = binary.BigEndian.AppendUint64(body, uint64(issued))
	body = binary.BigEndian.AppendUint64(body, uint64(expires))
	plan, _ := hex.DecodeString(p.Digest)
	body = append(body, plan...)
	policy := d.policyHash(p.Scope.Policy)
	body = append(body, policy[:]...)
	if p.Scope.Epoch != 0 {
		body = binary.BigEndian.AppendUint64(body, p.Scope.Epoch)
	}
	for _, v := range []string{p.Input.Name, p.Input.DisplayName} {
		body = binary.BigEndian.AppendUint16(body, uint16(len(v)))
		body = append(body, v...)
	}
	return body
}
func (d *NativeCreate) send(ctx context.Context, p adcreate.Plan, frame []byte) error {
	c, e := d.ldap.connect(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	request := ldap.NewAddRequest("CN="+p.Input.Name+","+d.ldap.Config.ManagedOU, nil)
	request.Attribute("identityLabCreate", []string{string(frame)})
	return c.Add(request)
}
func (d *NativeCreate) Encode(ctx context.Context, p adcreate.Plan) (adcreate.Wire, error) {
	actorBytes, _ := hex.DecodeString(d.pins.ActorSID)
	if !d.validPlan(p) || p.Actor != sid(actorBytes) || p.Expires <= time.Now().Unix() {
		return adcreate.Wire{}, ErrDenied
	}
	wire := d.frame(p)
	return adcreate.Wire{Bytes: wire, Expires: int64(binary.BigEndian.Uint64(wire[128:136]))}, nil
}
func (d *NativeCreate) Authorize(ctx context.Context, actor string, scope adcreate.Scope) error {
	if scope != d.scope {
		return ErrDenied
	}
	c, e := d.ldap.connect(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	row, e := one(c, d.ldap.Config.BaseDN, ldap.ScopeWholeSubtree, "(objectSid="+ldap.EscapeFilter(actor)+")", []string{"objectGUID", "objectSid", "userAccountControl", "memberOf"})
	if e != nil || rawGUID(row) != d.pins.ActorGUID || sid(row.GetRawAttributeValue("objectSid")) != actor || row.GetAttributeValue("userAccountControl") != "512" {
		return ErrDenied
	}
	group, e := one(c, d.ldap.Config.OperatorGroupDN, ldap.ScopeBaseObject, "(objectClass=group)", []string{"objectGUID", "member"})
	if e != nil || rawGUID(group) != d.ldap.Config.OperatorGroupGUID {
		return ErrDenied
	}
	for _, dn := range group.GetAttributeValues("member") {
		if dn == row.DN {
			return nil
		}
	}
	return ErrDenied
}
func (d *NativeCreate) Create(ctx context.Context, bound adcreate.BoundRequest) (adcreate.Result, error) {
	p := bound.Plan
	if p.Scope != d.scope {
		return adcreate.Result{}, ErrDenied
	}
	if d.validateBound(bound, true) != nil {
		return adcreate.Result{}, ErrDenied
	}
	if d.Ready(ctx) != nil || d.Authorize(ctx, p.Actor, p.Scope) != nil {
		return adcreate.Result{}, ErrDenied
	}
	if d.send(ctx, p, bound.Wire.Bytes) != nil {
		return adcreate.Result{}, ErrUncertain
	}
	confirmed, e := d.Receipt(ctx, bound)
	if e != nil {
		return adcreate.Result{}, e
	}
	c, e := d.ldap.connect(ctx)
	if e != nil {
		return adcreate.Result{}, e
	}
	defer c.Close()
	row, e := one(c, "CN="+p.Input.Name+","+d.ldap.Config.ManagedOU, ldap.ScopeBaseObject, "(objectClass=user)", []string{"objectGUID", "objectSid", "uSNChanged", "userAccountControl", "sAMAccountName", "userPrincipalName", "displayName", "memberOf", "servicePrincipalName"})
	if e != nil || row.GetAttributeValue("userAccountControl") != "514" || row.GetAttributeValue("sAMAccountName") != p.Input.Name || row.GetAttributeValue("displayName") != p.Input.DisplayName || row.GetAttributeValue("userPrincipalName") != p.Input.Name+"@"+p.Scope.UPNSuffix || len(row.GetAttributeValues("memberOf")) != 0 || len(row.GetAttributeValues("servicePrincipalName")) != 0 {
		return adcreate.Result{}, ErrUncertain
	}
	readback := adcreate.Result{GUID: rawGUID(row), SID: sid(row.GetRawAttributeValue("objectSid")), Version: row.GetAttributeValue("uSNChanged")}
	if readback != confirmed {
		return adcreate.Result{}, ErrUncertain
	}
	return confirmed, nil
}

func (d *NativeCreate) Receipt(ctx context.Context, bound adcreate.BoundRequest) (adcreate.Result, error) {
	p := bound.Plan
	if d.validateBound(bound, false) != nil {
		return adcreate.Result{}, ErrDenied
	}
	raw, q, e := d.query(ctx, p, bound.Wire.Bytes)
	if e != nil {
		return adcreate.Result{}, ErrUncertain
	}
	pub, _ := hex.DecodeString(d.pins.ReceiptPublic)
	return verifyCreateReceipt(raw, q, pub, d.ldap.Config.DomainSID, time.Now().Unix())
}
func (d *NativeCreate) query(ctx context.Context, p adcreate.Plan, frame []byte) ([]byte, []byte, error) {
	q := []byte("SWCSTAT1")
	if p.Scope.Epoch != 0 {
		q[7] = '2'
	}
	q = append(q, frame[8:24]...)
	q = append(q, frame[136:168]...)
	sum := sha256.Sum256(frame[:len(frame)-64])
	q = append(q, sum[:]...)
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return nil, nil, e
	}
	q = append(q, nonce...)
	for _, v := range []string{p.Scope.Domain, p.Scope.DC, p.Scope.OU, d.pins.ActorGUID} {
		b, _ := hex.DecodeString(v)
		q = append(q, b...)
	}
	policy := d.policyHash(p.Scope.Policy)
	q = append(q, policy[:]...)
	scope, _ := hex.DecodeString(d.pins.Scope)
	q = append(q, scope...)
	now := uint64(time.Now().Unix())
	q = binary.BigEndian.AppendUint64(q, now)
	q = binary.BigEndian.AppendUint64(q, now+30)
	signed := append(append([]byte{}, q...), ed25519.Sign(d.private, q)...)
	c, e := d.ldap.connect(ctx)
	if e != nil {
		return nil, nil, e
	}
	defer c.Close()
	rows, e := c.Search(ldap.NewSearchRequest("CN=NativeCreateReceipt,"+d.ldap.Config.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(identityLabCreateStatus="+hex.EncodeToString(signed)+")", []string{"identityLabCreateReceipt"}, nil))
	if e != nil || len(rows.Entries) != 1 || len(rows.Referrals) != 0 {
		return nil, nil, ErrUncertain
	}
	values := rows.Entries[0].GetRawAttributeValues("identityLabCreateReceipt")
	if len(values) != 1 {
		return nil, nil, ErrUncertain
	}
	return values[0], q, nil
}
func (d *NativeCreate) validateBound(b adcreate.BoundRequest, fresh bool) error {
	actorBytes, _ := hex.DecodeString(d.pins.ActorSID)
	min, max := 268, 544
	if d.scope.Epoch != 0 {
		min, max = min+8, max+8
	}
	if !d.validPlan(b.Plan) || b.Plan.Actor != sid(actorBytes) || len(b.Wire.Bytes) < min || len(b.Wire.Bytes) > max {
		return ErrDenied
	}
	wire := b.Wire.Bytes
	expected := d.body(b.Plan, int64(binary.BigEndian.Uint64(wire[120:128])), int64(binary.BigEndian.Uint64(wire[128:136])))
	sum := sha256.Sum256(wire)
	issued, expires := binary.BigEndian.Uint64(wire[120:128]), binary.BigEndian.Uint64(wire[128:136])
	if len(expected)+64 != len(wire) || !bytes.Equal(expected, wire[:len(wire)-64]) ||
		!ed25519.Verify(d.private.Public().(ed25519.PublicKey), wire[:len(wire)-64], wire[len(wire)-64:]) || b.WireDigest != hex.EncodeToString(sum[:]) || expires > uint64(b.Plan.Expires) || expires <= issued || expires-issued > 60 || b.Wire.Expires != int64(expires) {
		return ErrDenied
	}
	if fresh && (issued > uint64(time.Now().Unix()) || expires <= uint64(time.Now().Unix())) {
		return ErrDenied
	}
	return nil
}
func verifyCreateReceipt(raw, q, pub []byte, domainSID string, now int64) (adcreate.Result, error) {
	if !validCreateReceipt(raw, q, pub, now) || raw[256] != 2 {
		return adcreate.Result{}, ErrUncertain
	}
	version := binary.BigEndian.Uint64(raw[257:265])
	size := int(raw[281])
	if version == 0 || bytes.Equal(raw[265:281], make([]byte, 16)) || size < 8 || size > 68 || !bytes.Equal(raw[282+size:350], make([]byte, 68-size)) {
		return adcreate.Result{}, ErrUncertain
	}
	identity := sid(raw[282 : 282+size])
	if !strings.HasPrefix(identity, domainSID+"-") {
		return adcreate.Result{}, ErrUncertain
	}
	return adcreate.Result{GUID: hex.EncodeToString(raw[265:281]), SID: identity, Version: strconv.FormatUint(version, 10)}, nil
}
func validCreateReceipt(raw, q, pub []byte, now int64) bool {
	if len(raw) != 430 || len(q) != 248 || len(pub) != 32 ||
		!bytes.Equal(q[:7], []byte("SWCSTAT")) || (q[7] != '1' && q[7] != '2') ||
		!bytes.Equal(raw[:7], []byte("SWCRECP")) || raw[7] != q[7] ||
		bytes.Equal(q[88:104], make([]byte, 16)) || !bytes.Equal(raw[8:256], q) ||
		!ed25519.Verify(pub, raw[:366], raw[366:]) {
		return false
	}
	issued, expires := binary.BigEndian.Uint64(raw[350:358]), binary.BigEndian.Uint64(raw[358:366])
	if now < 0 || issued > uint64(now) || expires <= uint64(now) || expires <= issued || expires-issued > 30 || issued < binary.BigEndian.Uint64(q[232:240]) || expires > binary.BigEndian.Uint64(q[240:248]) {
		return false
	}
	return true
}
