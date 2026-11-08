package adprofile

// Laboratory codec/client only. No runtime backend or capability fallback.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func nativeValuesHash(values Values) []byte {
	var raw []byte
	for _, field := range []string{"displayName", "givenName", "sn", "mail"} {
		value := ""
		if len(values[field]) == 1 {
			value = values[field][0]
		}
		raw = binary.BigEndian.AppendUint16(raw, uint16(len(value)))
		raw = append(raw, value...)
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}

func nativeV2Body(p Plan, c Config, legacy []byte) ([]byte, error) {
	plan, err := hex.DecodeString(p.Digest)
	if err != nil || len(plan) != 32 || len(legacy) < 152 {
		return nil, ErrDenied
	}
	parent := make([]byte, 16)
	if p.Parent != "" {
		parent, err = hex.DecodeString(p.Parent)
		if err != nil || len(parent) != 16 {
			return nil, ErrDenied
		}
	}
	policy := sha256.Sum256([]byte(c.Revision))
	body := append([]byte("SWCAS002"), legacy[8:144]...)
	body = append(body, plan...)
	body = append(body, policy[:]...)
	body = append(body, parent...)
	body = append(body, nativeValuesHash(p.Before.Values)...)
	body = append(body, nativeValuesHash(p.After.Values)...)
	return append(body, legacy[144:]...), nil
}

func (d *nativeTestDirectory) receipt(ctx context.Context, id string) (nativeReceipt, error) {
	if d.pins.Protocol == 1 {
		return inspectNativeReceipt(ctx, id)
	}
	if d.pins.Protocol != 2 {
		return nativeReceipt{}, ErrDenied
	}
	_, p, err := d.journal.Get(ctx, id)
	if err != nil {
		return nativeReceipt{}, ErrUncertain
	}
	if p.Actor != d.actorSID || p.Target != d.pins.TargetGUID || p.Before.SID != d.targetSID || p.Policy != d.Config.Revision {
		return nativeReceipt{}, ErrDenied
	}
	var wire string
	if d.journal.DB.QueryRowContext(ctx, `SELECT wire_digest FROM lab_native_bindings WHERE id=$1 AND plan_digest=$2`, id, p.Digest).Scan(&wire) != nil {
		return nativeReceipt{}, ErrUncertain
	}
	decode := func(s string, n int) ([]byte, error) {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != n {
			return nil, ErrDenied
		}
		return b, nil
	}
	q := []byte("SWSTAT02")
	for _, field := range []struct {
		v string
		n int
	}{{id, 16}, {p.Digest, 32}, {wire, 32}} {
		b, e := decode(field.v, field.n)
		if e != nil {
			return nativeReceipt{}, e
		}
		q = append(q, b...)
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return nativeReceipt{}, err
	}
	q = append(q, nonce...)
	for _, v := range []string{d.Config.DomainGUID, d.Config.DCIdentity, p.Target, d.pins.ActorGUID} {
		b, e := decode(v, 16)
		if e != nil {
			return nativeReceipt{}, e
		}
		q = append(q, b...)
	}
	policy := sha256.Sum256([]byte(d.Config.Revision))
	q = append(q, policy[:]...)
	scope, e := decode(d.pins.Scope, 32)
	if e != nil {
		return nativeReceipt{}, e
	}
	q = append(q, scope...)
	now := time.Now().Unix()
	q = binary.BigEndian.AppendUint64(q, uint64(now))
	q = binary.BigEndian.AppendUint64(q, uint64(now+30))
	if len(q) != 248 {
		return nativeReceipt{}, ErrDenied
	}
	signed := append(append([]byte{}, q...), ed25519.Sign(d.private, q)...)
	c, err := d.connect(ctx)
	if err != nil {
		return nativeReceipt{}, ErrUncertain
	}
	defer c.Close()
	base := "CN=NativeCASReceipt," + d.Config.BaseDN
	result, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false,
		"(identityLabStatus="+hex.EncodeToString(signed)+")", []string{"identityLabReceipt"}, nil))
	if err != nil {
		return nativeReceipt{}, fmt.Errorf("status-search-%s: %w", nativeErrorCode(err), ErrUncertain)
	}
	if len(result.Referrals) != 0 || len(result.Entries) != 1 || result.Entries[0].DN != base {
		return nativeReceipt{}, fmt.Errorf("status-shape: %w", ErrUncertain)
	}
	values := result.Entries[0].GetRawAttributeValues("identityLabReceipt")
	if len(values) != 1 {
		return nativeReceipt{}, ErrUncertain
	}
	public, err := decode(d.pins.ReceiptPublic, 32)
	if err != nil {
		return nativeReceipt{}, err
	}
	return verifyNativeV2Receipt(values[0], q, public, p, time.Now().Unix())
}

func verifyNativeV2Receipt(raw, query, public []byte, p Plan, now int64) (nativeReceipt, error) {
	bad := func() (nativeReceipt, error) { return nativeReceipt{}, ErrUncertain }
	if len(raw) != 457 || len(query) != 248 || len(public) != 32 || !bytes.Equal(raw[:8], []byte("SWRECP02")) ||
		!bytes.Equal(raw[8:256], query) || !ed25519.Verify(public, raw[:393], raw[393:]) {
		return bad()
	}
	issued, expires := binary.BigEndian.Uint64(raw[377:385]), binary.BigEndian.Uint64(raw[385:393])
	qIssued, qExpires := binary.BigEndian.Uint64(query[232:240]), binary.BigEndian.Uint64(query[240:248])
	if now < 0 || issued > uint64(now) || expires <= uint64(now) || expires <= issued || expires-issued > 30 ||
		issued < qIssued || expires > qExpires || qExpires <= qIssued || qExpires-qIssued > 30 {
		return bad()
	}
	state := int(raw[256])
	version := binary.BigEndian.Uint64(raw[257:265])
	if state < 0 || state > 3 || (state == 2 && version == 0) || (state != 2 && version != 0) {
		return bad()
	}
	if state != 0 {
		parent := make([]byte, 16)
		if p.Parent != "" {
			var err error
			parent, err = hex.DecodeString(p.Parent)
			if err != nil {
				return bad()
			}
		}
		if !bytes.Equal(raw[265:281], parent) || !bytes.Equal(raw[281:313], nativeValuesHash(p.Before.Values)) ||
			!bytes.Equal(raw[313:345], nativeValuesHash(p.After.Values)) {
			return bad()
		}
	} else if !bytes.Equal(raw[265:345], make([]byte, 80)) {
		return bad()
	}
	reference := append(append([]byte{}, query[8:88]...), raw[265:281]...)
	reference = append(reference, raw[256:265]...)
	hash := sha256.Sum256(reference)
	if !bytes.Equal(hash[:], raw[345:377]) {
		return bad()
	}
	r := nativeReceipt{State: state, Digest: hex.EncodeToString(query[56:88])}
	if state == 2 {
		r.Version = strconv.FormatUint(version, 10)
	}
	return r, nil
}

func nativeErrorCode(err error) string {
	if err == nil {
		return "ok"
	}
	var protocol *ldap.Error
	if errors.As(err, &protocol) {
		for _, stage := range []string{"open", "lock", "record", "sign", "start", "cancel"} {
			if strings.Contains(protocol.Error(), "native-status-"+stage) {
				return strconv.Itoa(int(protocol.ResultCode)) + "-" + stage
			}
		}
		return strconv.Itoa(int(protocol.ResultCode))
	}
	return err.Error() // only locally generated, value-free receipt diagnostics
}

func TestNativeV2ReceiptValidation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Plan{ID: testID, Before: Snapshot{Values: Values{"displayName": {"Before"}}}, After: Snapshot{Values: Values{"displayName": {"After"}}}}
	q := make([]byte, 248)
	copy(q, []byte("SWSTAT02"))
	id, _ := hex.DecodeString(p.ID)
	copy(q[8:], id)
	copy(q[24:56], nativeValuesHash(p.Before.Values))
	copy(q[56:88], nativeValuesHash(p.After.Values))
	q[88] = 1
	binary.BigEndian.PutUint64(q[232:240], 1000)
	binary.BigEndian.PutUint64(q[240:248], 1030)
	raw := make([]byte, 393)
	copy(raw, []byte("SWRECP02"))
	copy(raw[8:256], q)
	raw[256] = 2
	binary.BigEndian.PutUint64(raw[257:265], 11)
	copy(raw[281:313], nativeValuesHash(p.Before.Values))
	copy(raw[313:345], nativeValuesHash(p.After.Values))
	reference := append(append([]byte{}, q[8:88]...), raw[265:281]...)
	reference = append(reference, raw[256:265]...)
	sum := sha256.Sum256(reference)
	copy(raw[345:377], sum[:])
	binary.BigEndian.PutUint64(raw[377:385], 1000)
	binary.BigEndian.PutUint64(raw[385:393], 1030)
	sign := func(body []byte) []byte { return append(append([]byte{}, body...), ed25519.Sign(private, body)...) }
	valid := sign(raw)
	if result, err := verifyNativeV2Receipt(valid, q, public, p, 1001); err != nil || result.State != 2 || result.Version != "11" {
		t.Fatal("valid receipt rejected")
	}
	if _, err := verifyNativeV2Receipt(valid, q, other, p, 1001); err == nil {
		t.Fatal("wrong receipt key accepted")
	}
	if _, err := verifyNativeV2Receipt(valid, q, public, p, 1030); err == nil {
		t.Fatal("expired receipt accepted")
	}
	freshQuery := append([]byte{}, q...)
	freshQuery[88] ^= 1
	if _, err := verifyNativeV2Receipt(valid, freshQuery, public, p, 1001); err == nil {
		t.Fatal("replayed nonce accepted")
	}
	for _, offset := range []int{0, 8, 16, 32, 88, 104, 168, 200, 256, 257, 265, 281, 313, 345, 377, 385} {
		changed := append([]byte{}, raw...)
		changed[offset] ^= 1
		if _, err := verifyNativeV2Receipt(sign(changed), q, public, p, 1001); err == nil {
			t.Fatalf("signed semantic mutation accepted at %d", offset)
		}
	}
	for _, broken := range [][]byte{valid[:len(valid)-1], append(append([]byte{}, valid...), 0), make([]byte, 457)} {
		if _, err := verifyNativeV2Receipt(broken, q, public, p, 1001); err == nil {
			t.Fatal("bad receipt frame accepted")
		}
	}
}
