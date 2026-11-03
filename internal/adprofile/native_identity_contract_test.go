package adprofile

// PREPARATION ONLY. No production adapter, factory, configuration flag or
// capability fallback is introduced. The entire binding lives in _test.go.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type nativePins struct {
	TargetDN   string `json:"target_dn"`
	ActorGUID  string `json:"actor_guid"`
	ActorSID   string `json:"actor_sid"` // NDR SID bytes, not a claimed username
	WriterGUID string `json:"writer_guid"`
	TargetGUID string `json:"target_guid"`
}

type nativeReceipt struct {
	State   int    `json:"state"`
	Digest  string `json:"digest"`
	Version string `json:"version"`
}

// nativePlanBody defines the proposed trusted issuer's projection. SWCAS001
// does NOT itself carry Plan.Digest, Policy or Parent: these remain explicit
// activation gates, not silently invented fields in the existing DC protocol.
func nativePlanBody(p Plan, c Config, pins nativePins, actorSID, targetSID string, now int64) ([]byte, error) {
	if now <= 0 || actorSID == "" || targetSID == "" || actorSID == targetSID || !idPattern.MatchString(p.ID) || p.Digest != digest(p) || p.Actor != actorSID || p.Policy != c.Revision ||
		p.Target != pins.TargetGUID || p.Before.GUID != p.Target || p.Before.SID != targetSID ||
		p.Before.DN != pins.TargetDN || p.Before.DC != c.DCIdentity || p.Expires <= now || p.Expires > now+300 ||
		(p.Parent != "" && (!idPattern.MatchString(p.Parent) || p.Parent == p.ID)) {
		return nil, ErrDenied
	}
	after := p.After
	after.Values = p.Before.Values
	if !reflect.DeepEqual(after, p.Before) || reflect.DeepEqual(p.Before.Values, p.After.Values) {
		return nil, ErrDenied
	}
	for _, values := range []Values{p.Before.Values, p.After.Values} {
		if len(values) != 4 || validateValues(values) != nil {
			return nil, ErrDenied
		}
		for _, field := range []string{"displayName", "givenName", "sn", "mail"} {
			v, ok := values[field]
			if !ok {
				return nil, ErrDenied
			}
			for _, value := range v {
				for _, b := range []byte(value) {
					if b < 32 || b > 126 {
						return nil, ErrDenied
					}
				}
			}
		}
	}
	version, err := strconv.ParseUint(p.Before.Version, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != p.Before.Version {
		return nil, ErrDenied
	}
	body := []byte("SWCAS001")
	for _, value := range []string{p.ID, c.DomainGUID, c.DCIdentity, p.Target, pins.ActorGUID, pins.WriterGUID, c.OperatorGroupGUID} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 16 {
			return nil, ErrDenied
		}
		body = append(body, decoded...)
	}
	expires := now + 60
	if p.Expires < expires {
		expires = p.Expires
	}
	for _, n := range []uint64{version, uint64(now), uint64(expires)} {
		body = binary.BigEndian.AppendUint64(body, n)
	}
	for _, field := range []string{"displayName", "givenName", "sn", "mail"} {
		if reflect.DeepEqual(p.Before.Values[field], p.After.Values[field]) {
			body = binary.BigEndian.AppendUint16(body, 65535)
			continue
		}
		value := ""
		if len(p.After.Values[field]) == 1 {
			value = p.After.Values[field][0]
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(value)))
		body = append(body, value...)
	}
	return body, nil
}

func TestNativePlanProjectionContract(t *testing.T) {
	if err := (&nativeTestDirectory{}).Modify(context.Background(), "actor", Snapshot{}, nil); !errors.Is(err, ErrDenied) {
		t.Fatal("unbound old interface accepted")
	}
	now := int64(1000)
	c := Config{DomainGUID: strings.Repeat("a", 32), DCIdentity: strings.Repeat("b", 32), OperatorGroupGUID: strings.Repeat("c", 32), Revision: "lab-policy"}
	pins := nativePins{TargetGUID: testTarget, TargetDN: "CN=synthetic", ActorGUID: strings.Repeat("d", 32), WriterGUID: strings.Repeat("e", 32)}
	before := Snapshot{GUID: testTarget, SID: "target", DN: pins.TargetDN, Version: "10", DC: c.DCIdentity,
		Values: Values{"displayName": {"Before"}, "givenName": nil, "sn": nil, "mail": nil}}
	p := Plan{ID: testID, Actor: "actor", Target: testTarget, Policy: c.Revision, Before: before, After: before, Expires: now + 30}
	p.After.Values = clone(before.Values)
	p.After.Values["displayName"] = []string{"After"}
	p.Digest = digest(p)
	body, err := nativePlanBody(p, c, pins, "actor", "target", now)
	if err != nil || binary.BigEndian.Uint64(body[136:144]) != uint64(p.Expires) {
		t.Fatal("bounded projection failed")
	}
	for _, mutate := range []func(*Plan){
		func(p *Plan) { p.Digest = "tampered" }, func(p *Plan) { p.Actor = "other"; p.Digest = digest(*p) },
		func(p *Plan) { p.Policy = "other"; p.Digest = digest(*p) }, func(p *Plan) { p.Before.SID = "other"; p.Digest = digest(*p) },
		func(p *Plan) { p.Expires = now; p.Digest = digest(*p) }, func(p *Plan) { p.Parent = p.ID; p.Digest = digest(*p) },
		func(p *Plan) { p.After.DC = "other"; p.Digest = digest(*p) },
		func(p *Plan) { p.Before.Values["sn"] = []string{"Müller"}; p.Digest = digest(*p) },
	} {
		candidate := p
		candidate.Before.Values = clone(p.Before.Values)
		candidate.After.Values = clone(p.After.Values)
		mutate(&candidate)
		if _, err := nativePlanBody(candidate, c, pins, "actor", "target", now); err == nil {
			t.Fatal("unsafe plan projection accepted")
		}
	}
}

type nativeBindingKey struct{}
type nativeBinding struct{ ID, Digest string }

type nativeTestDirectory struct {
	*LDAP
	pins                nativePins
	journal             *Journal
	actorSID, targetSID string
	private             ed25519.PrivateKey
	sends               int
	beforeSend          func()
	beforeInversePlan   func()
	loseReply           bool
}

func (d *nativeTestDirectory) Ready(ctx context.Context) error {
	// Not capability negotiation: this is an explicitly opted-in synthetic test.
	if os.Getenv("IDENTITY_NATIVE_IDENTITY_LAB") != "1" || d.Config.URL != "ldaps://dc1.profile.test:636" ||
		d.Config.BaseDN != "DC=profile,DC=test" {
		return ErrDenied
	}
	_, err := d.LDAP.Read(ctx, d.pins.TargetGUID, d.actorSID)
	return err
}

func inspectNativeReceipt(ctx context.Context, id string) (nativeReceipt, error) {
	if !idPattern.MatchString(id) {
		return nativeReceipt{}, ErrDenied
	}
	// Privileged fixture inspection ONLY. This is not a production receipt API.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "/workspace/scripts/ad-profile-lab/native_receipt.py", id)
	out, err := command.Output()
	if err != nil || len(out) > 1024 {
		return nativeReceipt{}, ErrUncertain
	}
	var r nativeReceipt
	if json.Unmarshal(out, &r) != nil {
		return r, ErrUncertain
	}
	return r, nil
}

func (d *nativeTestDirectory) Modify(ctx context.Context, actor string, before Snapshot, changes Values) error {
	binding, ok := ctx.Value(nativeBindingKey{}).(nativeBinding)
	if !ok {
		return ErrDenied
	}
	op, p, err := d.journal.Get(ctx, binding.ID)
	if err != nil || op.State != "applying" || p.Digest != binding.Digest || actor != p.Actor || !reflect.DeepEqual(before, p.Before) {
		return ErrDenied
	}
	want := Values{}
	for a, v := range p.After.Values {
		if !reflect.DeepEqual(v, p.Before.Values[a]) {
			want[a] = v
		}
	}
	if !reflect.DeepEqual(want, changes) {
		return ErrDenied
	}
	if p.Parent != "" {
		parentOp, parent, parentErr := d.journal.Get(ctx, p.Parent)
		var parentWire string
		if parentErr != nil || parentOp.State != "succeeded" || parent.Actor != p.Actor || parent.Target != p.Target ||
			!reflect.DeepEqual(p.Before.Values, parent.After.Values) || !reflect.DeepEqual(p.After.Values, parent.Before.Values) ||
			d.journal.DB.QueryRowContext(ctx, `SELECT wire_digest FROM lab_native_bindings WHERE id=$1 AND plan_digest=$2`, parent.ID, parent.Digest).Scan(&parentWire) != nil {
			return ErrDenied
		}
		receipt, receiptErr := inspectNativeReceipt(ctx, parent.ID)
		if receiptErr != nil || receipt.State != 2 || receipt.Digest != parentWire || receipt.Version != p.Before.Version {
			return ErrDenied
		}
	}
	body, err := nativePlanBody(p, d.Config, d.pins, d.actorSID, d.targetSID, time.Now().Unix())
	if err != nil {
		return ErrDenied
	}
	sum := sha256.Sum256(body)
	wireDigest := hex.EncodeToString(sum[:])
	meta, _ := json.Marshal(struct{ PlanDigest, WireDigest, Policy, Parent string }{p.Digest, wireDigest, p.Policy, p.Parent})
	// Correlation and its audit are durably stored before any send. No raw packet,
	// profile value, password or key is stored in this laboratory metadata table.
	tx, err := d.journal.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrDenied
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO lab_native_bindings VALUES($1,$2,$3)`, p.ID, p.Digest, wireDigest); err != nil {
		return ErrDenied
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ad_profile_audit VALUES($1,$2,$3,'native_dispatch_prepared',$4,$5)`, p.ID, p.Actor, p.Target, time.Now().Unix(), string(meta)); err != nil {
		return ErrDenied
	}
	if tx.Commit() != nil {
		return ErrUncertain
	}
	if d.beforeSend != nil {
		d.beforeSend()
	}
	c, err := d.connect(ctx)
	if err != nil {
		return ErrDenied
	}
	defer c.Close()
	packet := append(body, ed25519.Sign(d.private, body)...)
	req := ldap.NewModifyRequest(p.Before.DN, nil)
	req.Replace("identityLabCAS", []string{string(packet)})
	d.sends++
	err = c.Modify(req)
	if d.loseReply {
		return ErrUncertain
	}
	r, receiptErr := inspectNativeReceipt(ctx, p.ID)
	if receiptErr != nil || r.Digest != wireDigest {
		return ErrUncertain
	}
	if r.State == 3 {
		return ErrDenied
	}
	if err != nil || r.State != 2 || r.Version == "" {
		return ErrUncertain
	}
	return nil
}

// The context binding is a test-harness workaround for the OLD interface's
// missing ID/digest. A real adapter must get an explicit typed command instead.
func nativeHandle(ctx context.Context, s *Service, d *nativeTestDirectory, r Request) (Response, error) {
	var inverseBefore *Snapshot
	if r.Action == "reconcile" {
		return Response{}, ErrUncertain
	} // value observation never unlocks the native claim
	if r.Action == "rollback-plan" {
		parentOperation, p, err := s.Journal.Get(ctx, r.Parent)
		if err != nil || parentOperation.State != "succeeded" {
			return Response{}, ErrDenied
		}
		actor, authErr := d.Authenticate(ctx, r.Username, r.Password)
		if authErr != nil || actor != p.Actor {
			return Response{}, ErrDenied
		}
		var wire string
		if s.Journal.DB.QueryRowContext(ctx, `SELECT wire_digest FROM lab_native_bindings WHERE id=$1 AND plan_digest=$2`, p.ID, p.Digest).Scan(&wire) != nil {
			return Response{}, ErrDenied
		}
		receipt, err := inspectNativeReceipt(ctx, p.ID)
		current, readErr := d.Read(ctx, p.Target, p.Actor)
		if err != nil || readErr != nil || receipt.State != 2 || receipt.Digest != wire || current.Version != receipt.Version ||
			current.GUID != p.Target || current.SID != p.Before.SID || current.DC != p.Before.DC || !reflect.DeepEqual(current.Values, p.After.Values) {
			return Response{}, ErrDenied
		}
		inverseBefore = &current
		if d.beforeInversePlan != nil {
			d.beforeInversePlan()
		}
	}
	if r.Action == "apply" {
		_, p, err := s.Journal.Get(ctx, r.ID)
		if err != nil {
			return Response{}, ErrDenied
		}
		ctx = context.WithValue(ctx, nativeBindingKey{}, nativeBinding{p.ID, p.Digest})
	}
	result, err := s.Handle(ctx, r)
	if err == nil && (r.Action == "prepare" || r.Action == "rollback-plan") && result.Operation.State == "prepared" {
		_, plan, readErr := s.Journal.Get(ctx, r.ID)
		_, projectionErr := nativePlanBody(plan, d.Config, d.pins, d.actorSID, d.targetSID, time.Now().Unix())
		if readErr != nil || projectionErr != nil {
			cancel := r
			cancel.Action = "cancel"
			_, _ = s.Handle(ctx, cancel)
			return Response{}, ErrDenied
		}
	}
	if err == nil && inverseBefore != nil {
		_, inverse, readErr := s.Journal.Get(ctx, r.ID)
		if readErr != nil || !reflect.DeepEqual(inverse.Before, *inverseBefore) {
			cancel := r
			cancel.Action = "cancel"
			_, _ = s.Handle(ctx, cancel) // failure leaves the plan fenced; apply rechecks the parent receipt too
			return Response{}, ErrDenied
		}
	}
	return result, err
}

func TestNativeIdentityLab(t *testing.T) {
	if os.Getenv("IDENTITY_NATIVE_IDENTITY_LAB") != "1" {
		t.Skip("explicit isolated native laboratory only")
	}
	if runtime.GOOS != "linux" || os.Getenv("IDENTITY_AD_PROFILE_LAB") != "/tmp/lab-config.json" {
		t.Fatal("invalid lab environment")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("networkless laboratory required")
	}
	var f struct{ Config Config }
	data, err := os.ReadFile("/tmp/lab-config.json")
	if err != nil || json.Unmarshal(data, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	var pins nativePins
	data, err = os.ReadFile("/tmp/native-cas/pins.json")
	if err != nil || json.Unmarshal(data, &pins) != nil {
		t.Fatal("native fixture unavailable")
	}
	base, err := NewLDAP(f.Config)
	if err != nil {
		t.Fatal("LDAP fixture unavailable")
	}
	ctx := context.Background()
	if base.Ready(ctx) == nil {
		t.Fatal("production RFC4528 CAS gate unexpectedly opened")
	}
	actor, err := base.Authenticate(ctx, "operator", base.password)
	if err != nil {
		t.Fatal("actor authentication failed")
	}
	actorRaw, _ := hex.DecodeString(pins.ActorSID)
	if actor != sid(actorRaw) {
		t.Fatal("actor pin mismatch")
	}
	original, err := base.Read(ctx, pins.TargetGUID, actor)
	if err != nil {
		t.Fatal("target unavailable")
	}
	adminChange := func(values Values) {
		t.Helper()
		c, err := base.connect(ctx)
		if err != nil {
			t.Fatal("fixture connection failed")
		}
		defer c.Close()
		if c.Bind("CN=Administrator,CN=Users,"+f.Config.BaseDN, base.password) != nil {
			t.Fatal("fixture admin bind failed")
		}
		req := ldap.NewModifyRequest(pins.TargetDN, nil)
		for a, v := range values {
			req.Replace(a, v)
		}
		if c.Modify(req) != nil {
			t.Fatal("fixture mutation failed")
		}
	}
	t.Cleanup(func() {
		adminChange(original.Values)
		restored, err := base.Read(context.Background(), pins.TargetGUID, actor)
		if err != nil || !reflect.DeepEqual(restored.Values, original.Values) {
			t.Error("fixture profile values not restored exactly")
		}
	})
	keyPEM, err := os.ReadFile("/tmp/native-cas/issuer.pem")
	if err != nil {
		t.Fatal("lab key unavailable")
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("lab key malformed")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal("lab key malformed")
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("wrong laboratory key type")
	}
	db, err := sql.Open("sqlite", "/tmp/native-cas/identity-contract.db")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err = db.Exec(Schema + `CREATE TABLE lab_native_bindings(id TEXT PRIMARY KEY,plan_digest TEXT NOT NULL,wire_digest TEXT NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	journalKey := make([]byte, 32)
	if _, err = rand.Read(journalKey); err != nil {
		t.Fatal(err)
	}
	j, err := NewJournal(db, journalKey)
	if err != nil {
		t.Fatal(err)
	}
	d := &nativeTestDirectory{LDAP: base, pins: pins, journal: j, actorSID: actor, targetSID: original.SID, private: private}
	s := &Service{Enabled: true, Policy: f.Config.Revision, Directory: d, Journal: j}
	freshService := func() { s = &Service{Enabled: true, Policy: f.Config.Revision, Directory: d, Journal: j} } // independent test scenarios; journals are never reset
	newID := func() string {
		v := make([]byte, 16)
		if _, err := rand.Read(v); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(v)
	}
	request := func(action, id string) Request {
		return Request{Action: action, ID: id, Username: "operator", Password: base.password, Target: pins.TargetGUID}
	}
	call := func(r Request) (Response, error) { return nativeHandle(ctx, s, d, r) }
	preparePlan := func(value string) Request {
		t.Helper()
		r := request("prepare", newID())
		r.Changes = Values{"displayName": {value}}
		if _, err := call(r); err != nil {
			t.Fatal("plan failed")
		}
		r.Action = "apply"
		r.Changes = nil
		return r
	}
	assertState := func(id, state string) {
		t.Helper()
		op, _, err := j.Get(ctx, id)
		if err != nil || op.State != state {
			t.Fatalf("wanted %s", state)
		}
	}
	mode := os.Getenv("IDENTITY_NATIVE_IDENTITY_CASE")
	if mode == "uncertain" || mode == "lost_reply" {
		r := preparePlan("Identity-Unclear")
		if mode == "uncertain" && os.WriteFile("/tmp/native-cas/fault", []byte("commit_ack_error"), 0600) != nil {
			t.Fatal("fault injection failed")
		}
		d.loseReply = mode == "lost_reply"
		t.Cleanup(func() { os.Remove("/tmp/native-cas/fault") })
		_, err := call(r)
		os.Remove("/tmp/native-cas/fault")
		if !errors.Is(err, ErrUncertain) {
			t.Fatal("unclear commit treated as certain")
		}
		assertState(r.ID, "reconciliation_required")
		receipt, err := inspectNativeReceipt(ctx, r.ID)
		if err != nil || (mode == "uncertain" && (receipt.State != 1 || receipt.Version != "")) ||
			(mode == "lost_reply" && (receipt.State != 2 || receipt.Version == "")) {
			t.Fatal("native receipt misclassified")
		}
		got, err := base.Read(ctx, pins.TargetGUID, actor)
		if err != nil || !reflect.DeepEqual(got.Values["displayName"], []string{"Identity-Unclear"}) {
			t.Fatal("expected committed effect missing")
		}
		for i := 0; i < 2; i++ {
			if _, err := call(r); err != nil {
				t.Fatal("status replay failed")
			}
		}
		if d.sends != 1 {
			t.Fatal("unclear operation replayed")
		}
		if _, err := call(request("reconcile", r.ID)); !errors.Is(err, ErrUncertain) {
			t.Fatal("observation unlocked native uncertainty")
		}
		next := request("prepare", newID())
		next.Changes = Values{"displayName": {"Fresh-ID"}}
		if _, err := call(next); err == nil {
			t.Fatal("unclear Identity target unlocked")
		}
		if j.Recover(ctx) != nil {
			t.Fatal("recovery failed")
		}
		assertState(r.ID, "reconciliation_required")
		unchanged, receiptErr := inspectNativeReceipt(ctx, r.ID)
		if receiptErr != nil || unchanged != receipt {
			t.Fatal("uncertain native claim changed during recovery")
		}
		return
	}
	// Real prepare -> encrypted claim -> signed LDAP -> native commit -> audit.
	r := preparePlan("Identity-Native")
	if _, err := call(r); err != nil {
		t.Fatal("native apply failed")
	}
	assertState(r.ID, "succeeded")
	committed, err := inspectNativeReceipt(ctx, r.ID)
	current, readErr := base.Read(ctx, pins.TargetGUID, actor)
	if err != nil || readErr != nil || committed.State != 2 || committed.Version != current.Version {
		t.Fatal("native committed version does not match actual result")
	}
	for i := 0; i < 2; i++ {
		if _, err := call(r); err != nil {
			t.Fatal("repeat status failed")
		}
	}
	if d.sends != 1 {
		t.Fatal("success replayed")
	}
	var originalWire string
	if db.QueryRow(`SELECT wire_digest FROM lab_native_bindings WHERE id=$1`, r.ID).Scan(&originalWire) != nil {
		t.Fatal("mapping missing")
	}
	if _, err := db.Exec(`UPDATE lab_native_bindings SET wire_digest=$1 WHERE id=$2`, strings.Repeat("0", 64), r.ID); err != nil {
		t.Fatal(err)
	}
	badInverse := request("rollback-plan", newID())
	badInverse.Parent = r.ID
	if _, err := call(badInverse); err == nil {
		t.Fatal("mismatched receipt accepted")
	}
	if _, err := db.Exec(`UPDATE lab_native_bindings SET wire_digest=$1 WHERE id=$2`, originalWire, r.ID); err != nil {
		t.Fatal(err)
	}
	rollback := request("rollback-plan", newID())
	rollback.Parent = r.ID
	if _, err := call(rollback); err != nil {
		t.Fatal("inverse plan failed")
	}
	rollback.Action = "apply"
	if _, err := call(rollback); err != nil {
		t.Fatal("inverse apply failed")
	}
	assertState(rollback.ID, "succeeded")
	restored, err := base.Read(ctx, pins.TargetGUID, actor)
	if err != nil || !reflect.DeepEqual(restored.Values, original.Values) {
		t.Fatal("inverse did not restore values")
	}
	// A foreign ABA between inverse receipt check and actual plan creation must
	// not turn the parent's committed version into a fresh, apparently owned one.
	freshService()
	r = preparePlan("Identity-Inverse-Race")
	if _, err := call(r); err != nil {
		t.Fatal("inverse race parent failed")
	}
	d.beforeInversePlan = func() {
		adminChange(Values{"displayName": {"Other"}})
		adminChange(Values{"displayName": {"Identity-Inverse-Race"}})
	}
	rollback = request("rollback-plan", newID())
	rollback.Parent = r.ID
	if _, err := call(rollback); err == nil {
		t.Fatal("inverse planning race accepted")
	}
	d.beforeInversePlan = nil
	assertState(rollback.ID, "cancelled")
	// Runtime permits Unicode, SWCAS001 does not: never offer an unexecutable
	// native plan as confirmed and never lose information through conversion.
	freshService()
	unsupported := request("prepare", newID())
	unsupported.Changes = Values{"displayName": {"Müller"}}
	sendsBefore := d.sends
	if _, err := call(unsupported); err == nil {
		t.Fatal("unsupported native value accepted")
	}
	assertState(unsupported.ID, "cancelled")
	if d.sends != sendsBefore {
		t.Fatal("unsupported plan sent")
	}
	// A-B-A before inverse planning is rejected by the authoritative native USN.
	freshService()
	r = preparePlan("Identity-Owned")
	if _, err := call(r); err != nil {
		t.Fatal("parent apply failed")
	}
	adminChange(Values{"displayName": {"External"}})
	adminChange(Values{"displayName": {"Identity-Owned"}})
	rollback = request("rollback-plan", newID())
	rollback.Parent = r.ID
	if _, err := call(rollback); err == nil {
		t.Fatal("foreign ABA accepted for inverse")
	}
	// A race after Identity's pre-read is rejected by the native whole-object CAS.
	freshService()
	r = preparePlan("Must-Not-Apply")
	d.beforeSend = func() { adminChange(Values{"givenName": {"Foreign-Keep"}}) }
	if _, err := call(r); err != nil {
		t.Fatal("confirmed no-effect did not finish")
	}
	d.beforeSend = nil
	assertState(r.ID, "failed_no_effect")
	got, err := base.Read(ctx, pins.TargetGUID, actor)
	if err != nil || !reflect.DeepEqual(got.Values["givenName"], []string{"Foreign-Keep"}) {
		t.Fatal("foreign value lost")
	}
	// Explicit operator cancellation never sends a native request.
	freshService()
	r = preparePlan("Cancelled")
	r.Action = "cancel"
	sends := d.sends
	if _, err := call(r); err != nil {
		t.Fatal("cancel failed")
	}
	r.Action = "apply"
	call(r)
	if d.sends != sends {
		t.Fatal("cancelled operation dispatched")
	}
	// Identity result commit loss cannot be repaired by replay or a read alone.
	freshService()
	r = preparePlan("Identity-Finish-Lost")
	if _, err = db.Exec(`CREATE TRIGGER lab_finish_failure BEFORE UPDATE OF state ON ad_profile_operations WHEN NEW.state='succeeded' BEGIN SELECT RAISE(ABORT,'synthetic finish loss'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := call(r); !errors.Is(err, ErrUncertain) {
		t.Fatal("finish failure treated as safe")
	}
	assertState(r.ID, "applying")
	if _, err = db.Exec(`DROP TRIGGER lab_finish_failure`); err != nil {
		t.Fatal(err)
	}
	if j.Recover(ctx) != nil {
		t.Fatal("exclusive startup recovery failed")
	}
	assertState(r.ID, "reconciliation_required")
	sends = d.sends
	call(r)
	if d.sends != sends {
		t.Fatal("recovery replayed a native write")
	}
	// No credential/profile plaintext in either Identity audit or encrypted payload.
	rows, err := db.Query(`SELECT metadata FROM ad_profile_audit UNION ALL SELECT payload FROM ad_profile_operations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if rows.Scan(&value) != nil {
			t.Fatal("audit read failed")
		}
		for _, secret := range []string{base.password, "Identity-Native", "Identity-Owned", "Identity-Finish-Lost"} {
			if strings.Contains(value, secret) {
				t.Fatal("sensitive audit/payload disclosure")
			}
		}
	}
	if rows.Err() != nil {
		t.Fatal("audit iteration failed")
	}
	var count int
	if db.QueryRow(`SELECT COUNT(*) FROM ad_profile_audit WHERE event='native_dispatch_prepared'`).Scan(&count) != nil || count != d.sends {
		t.Fatal("dispatch audit mismatch")
	}
}

// Compile-time and ordinary-test checks keep this prototype out of binaries.
var _ Directory = (*nativeTestDirectory)(nil)
