package adprofile

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const testID = "11111111111111111111111111111111"
const testTarget = "22222222222222222222222222222222"

func ldapModify(dn, attr string) *ldap.ModifyRequest {
	r := ldap.NewModifyRequest(dn, nil)
	v := "forbidden"
	if attr == "userAccountControl" {
		v = "514"
	}
	r.Replace(attr, []string{v})
	return r
}

type fakeDirectory struct {
	mu        sync.Mutex
	current   Snapshot
	calls     int
	deny      bool
	uncertain bool
}

func (f *fakeDirectory) Ready(context.Context) error { return nil }

func (f *fakeDirectory) Authenticate(context.Context, string, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deny {
		return "", ErrDenied
	}
	return "actor", nil
}
func (f *fakeDirectory) Read(context.Context, string, string) (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.current
	v.Values = clone(v.Values)
	return v, nil
}
func (f *fakeDirectory) Modify(_ context.Context, _ string, b Snapshot, v Values) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if !reflect.DeepEqual(b, f.current) {
		return ErrDenied
	}
	for a, x := range v {
		f.current.Values[a] = x
	}
	f.current.Version = "2"
	if f.uncertain {
		return ErrUncertain
	}
	return nil
}
func fixture(t *testing.T) (*Service, *fakeDirectory) {
	t.Helper()
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), "journal.db"))
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, e = db.Exec(Schema); e != nil {
		t.Fatal(e)
	}
	j, e := NewJournal(db, []byte(strings.Repeat("k", 32)))
	if e != nil {
		t.Fatal(e)
	}
	f := &fakeDirectory{current: Snapshot{GUID: testTarget, SID: "target", DN: "CN=fixture,OU=Managed,DC=example,DC=test", Version: "1", DC: "dc", Values: Values{"displayName": {"Before"}, "givenName": nil, "sn": nil, "mail": nil}}}
	return &Service{Enabled: true, Policy: "test", Directory: f, Journal: j}, f
}
func prepare(t *testing.T, s *Service) Request {
	t.Helper()
	r := Request{Action: "prepare", Username: "operator", Password: "synthetic", ID: testID, Target: testTarget, Changes: Values{"displayName": {"After"}}}
	if _, e := s.Handle(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	r.Action = "apply"
	r.Changes = nil
	return r
}
func TestDisabledAndAttributePolicy(t *testing.T) {
	for _, attr := range []string{"servicePrincipalName", "sIDHistory", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink", "memberOf"} {
		if !hasRiskValues(ldap.NewEntry("CN=synthetic", map[string][]string{attr: {"synthetic"}})) {
			t.Fatalf("risk attribute ignored: %s", attr)
		}
	}
	for _, v := range []Values{{"userAccountControl": {"512"}}, {"unicodePwd": {"secret"}}, {"displayName": {"a", "b"}}, {"mail": {"invalid"}}, {"sn": {" bad"}}, {"givenName": {"bad\x00"}}, nil} {
		if validateValues(v) == nil {
			t.Fatalf("accepted %v", v)
		}
	}
	if validateValues(Values{"sn": nil}) != nil {
		t.Fatal("explicit deletion rejected")
	}
	s, f := fixture(t)
	s.Enabled = false
	if _, e := s.Handle(context.Background(), Request{ID: testID}); e == nil || f.calls != 0 {
		t.Fatal("disabled service active")
	}
}
func TestProfileSuccessRollbackAndNoReplay(t *testing.T) {
	s, f := fixture(t)
	r := prepare(t, s)
	result, e := s.Handle(context.Background(), r)
	if e != nil || result.Operation.State != "succeeded" {
		t.Fatalf("apply: %v %s", e, result.Operation.State)
	}
	for i := 0; i < 2; i++ {
		if _, e = s.Handle(context.Background(), r); e != nil {
			t.Fatal(e)
		}
	}
	if f.calls != 1 {
		t.Fatal("replay")
	}
	rollback := Request{Action: "prepare", ID: strings.Repeat("3", 32), Username: r.Username, Password: r.Password, Target: testTarget, Changes: Values{"displayName": {"Before"}}, Parent: testID}
	if _, e = s.Handle(context.Background(), rollback); e != nil {
		t.Fatal(e)
	}
	rollback.Action = "apply"
	if _, e = s.Handle(context.Background(), rollback); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(f.current.Values["displayName"], []string{"Before"}) {
		t.Fatal("rollback did not restore exact values")
	}
	var payload string
	if e = s.Journal.DB.QueryRow(`SELECT payload FROM ad_profile_operations WHERE id=$1`, testID).Scan(&payload); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(payload, "Before") || strings.Contains(payload, "After") {
		t.Fatal("PII stored in plaintext")
	}
	rows, e := s.Journal.DB.Query(`SELECT event FROM ad_profile_audit`)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var event string
		rows.Scan(&event)
		if strings.Contains(event, "After") {
			t.Fatal("audit contains values")
		}
	}
}
func TestAuditFailureAndUncertainNoReplay(t *testing.T) {
	for _, phase := range []string{"applying", "succeeded"} {
		t.Run(phase, func(t *testing.T) {
			s, f := fixture(t)
			r := prepare(t, s)
			_, e := s.Journal.DB.Exec(`CREATE TRIGGER reject_audit BEFORE INSERT ON ad_profile_audit WHEN NEW.event='` + phase + `' BEGIN SELECT RAISE(ABORT,'synthetic'); END`)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Handle(context.Background(), r); e == nil {
				t.Fatal("audit failure accepted")
			}
			want := 0
			if phase == "succeeded" {
				want = 1
			}
			if f.calls != want {
				t.Fatal("side effect escaped claim boundary")
			}
			if phase == "succeeded" {
				if _, e = s.Handle(context.Background(), r); e != nil {
					t.Fatal(e)
				}
				if f.calls != 1 {
					t.Fatal("uncertain operation replayed")
				}
				r.Action = "reconcile"
				if e = s.Journal.Recover(context.Background()); e != nil {
					t.Fatal(e)
				}
				if _, e = s.Handle(context.Background(), r); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
	s, f := fixture(t)
	r := prepare(t, s)
	f.uncertain = true
	result, e := s.Handle(context.Background(), r)
	if e != ErrUncertain || result.Operation.State != "reconciliation_required" {
		t.Fatal("ambiguous result not blocked")
	}
	s.Handle(context.Background(), r)
	if f.calls != 1 {
		t.Fatal("ambiguous result replayed")
	}
}
func TestRevocationConflictCancelAndTamper(t *testing.T) {
	for _, mode := range []string{"revoked", "changed", "expired", "policy", "cancelled", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			s, f := fixture(t)
			r := prepare(t, s)
			switch mode {
			case "revoked":
				f.deny = true
			case "changed":
				f.current.Version = "external"
			case "expired":
				s.Journal.DB.Exec(`UPDATE ad_profile_operations SET expires=0`)
			case "policy":
				s.Policy = "new"
			case "cancelled":
				r.Action = "cancel"
				if _, e := s.Handle(context.Background(), r); e != nil {
					t.Fatal(e)
				}
				r.Action = "apply"
			case "tampered":
				s.Journal.DB.Exec(`UPDATE ad_profile_operations SET payload='invalid'`)
			}
			s.Handle(context.Background(), r)
			if f.calls != 0 {
				t.Fatal("guard bypass")
			}
		})
	}
	s, f := fixture(t)
	r := prepare(t, s)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Handle(context.Background(), r) }()
	}
	wg.Wait()
	if f.calls != 1 {
		t.Fatal("concurrent replay")
	}
}

func TestPrepareAuditExpiryIdempotencyAndRetention(t *testing.T) {
	s, f := fixture(t)
	if _, e := s.Journal.DB.Exec(`CREATE TRIGGER reject_prepare BEFORE INSERT ON ad_profile_audit WHEN NEW.event='prepared' BEGIN SELECT RAISE(ABORT,'synthetic'); END`); e != nil {
		t.Fatal(e)
	}
	r := Request{Action: "prepare", Username: "operator", Password: "synthetic", ID: testID, Target: testTarget, Changes: Values{"displayName": {"After"}}}
	if _, e := s.Handle(context.Background(), r); e == nil {
		t.Fatal("prepare audit failure accepted")
	}
	var count int
	s.Journal.DB.QueryRow(`SELECT count(*) FROM ad_profile_operations`).Scan(&count)
	if count != 0 || f.calls != 0 {
		t.Fatal("failed intent persisted")
	}
	s.Journal.DB.Exec(`DROP TRIGGER reject_prepare`)
	if _, e := s.Handle(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Handle(context.Background(), r); e != nil {
		t.Fatal("idempotent plan rejected", e)
	}
	r.Changes = Values{"displayName": {"conflict"}}
	if _, e := s.Handle(context.Background(), r); e == nil {
		t.Fatal("idempotency conflict accepted")
	}
	r.Action = "cancel"
	if _, e := s.Handle(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	if e := s.Journal.Erase(context.Background(), time.Now().Add(8*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	op, p, e := s.Journal.Get(context.Background(), testID)
	if e != nil || op.State != "cancelled" || len(p.Before.Values) != 0 {
		t.Fatal("retention erased evidence or retained values")
	}
	r.Action = "status"
	if result, e := s.Handle(context.Background(), r); e != nil || len(result.Events) == 0 {
		t.Fatal("metadata unavailable after erasure")
	}
	r.Action = "apply"
	s.Handle(context.Background(), r)
	if f.calls != 0 {
		t.Fatal("erased plan replayed")
	}
	s, f = fixture(t)
	before := f.current
	after := before
	after.Values = clone(before.Values)
	after.Values["displayName"] = []string{"After"}
	expired := Plan{ID: testID, Actor: "actor", Target: testTarget, Policy: "test", Before: before, After: after, Expires: time.Now().Add(-time.Minute).Unix()}
	expired.Digest = digest(expired)
	if e = s.Journal.Prepare(context.Background(), expired); e != nil {
		t.Fatal(e)
	}
	r.Action = "apply"
	if result, e := s.Handle(context.Background(), r); e != nil || result.Operation.State != "expired" || f.calls != 0 {
		t.Fatal("expired confirmation accepted")
	}
}

func TestJournalBackupRestorePreservesNoReplay(t *testing.T) {
	s, f := fixture(t)
	r := prepare(t, s)
	if _, e := s.Handle(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(t.TempDir(), "journal-copy.db")
	if _, e := s.Journal.DB.Exec(`VACUUM INTO $1`, backup); e != nil {
		t.Fatal("consistent synthetic snapshot failed", e)
	}
	db, e := sql.Open("sqlite", backup)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	restored, e := NewJournal(db, []byte(strings.Repeat("k", 32)))
	if e != nil {
		t.Fatal(e)
	}
	if e = restored.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	replacement := &Service{Enabled: true, Policy: s.Policy, Directory: f, Journal: restored}
	if result, e := replacement.Handle(context.Background(), r); e != nil || result.Operation.State != "succeeded" || f.calls != 1 {
		t.Fatal("restored completed operation replayed")
	}
	history, e := restored.History(context.Background(), r.ID)
	if e != nil || len(history) != 3 {
		t.Fatal("restored audit evidence changed")
	}
	wrong, e := NewJournal(db, []byte(strings.Repeat("x", 32)))
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = wrong.Get(context.Background(), r.ID); e == nil {
		t.Fatal("wrong recovery key accepted")
	}
}

func TestRollbackRejectsForeignChangesAndCancelRace(t *testing.T) {
	s, f := fixture(t)
	r := prepare(t, s)
	if _, e := s.Handle(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	f.current.Values["displayName"] = []string{"Foreign"}
	rollback := Request{Action: "rollback-plan", ID: strings.Repeat("3", 32), Username: r.Username, Password: r.Password, Parent: testID}
	if _, e := s.Handle(context.Background(), rollback); e == nil || f.calls != 1 {
		t.Fatal("foreign change overwritten")
	}
	s, f = fixture(t)
	r = prepare(t, s)
	var wg sync.WaitGroup
	for _, action := range []string{"apply", "cancel"} {
		wg.Add(1)
		go func(action string) {
			defer wg.Done()
			request := r
			request.Action = action
			s.Handle(context.Background(), request)
		}(action)
	}
	wg.Wait()
	op, _, e := s.Journal.Get(context.Background(), testID)
	if e != nil {
		t.Fatal(e)
	}
	if (op.State == "cancelled" && f.calls != 0) || (op.State == "succeeded" && f.calls != 1) || (op.State != "cancelled" && op.State != "succeeded") {
		t.Fatal("cancel/claim race inconsistent")
	}
}

func TestUnchangedReadCannotResolveUncertainWrite(t *testing.T) {
	s, f := fixture(t)
	r := prepare(t, s)
	op, _, e := s.Journal.Get(context.Background(), r.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Journal.Change(context.Background(), op, "prepared", "applying"); e != nil {
		t.Fatal(e)
	}
	if e = s.Journal.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	r.Action = "reconcile"
	if result, e := s.Handle(context.Background(), r); e != ErrUncertain || result.Operation.State != "reconciliation_required" {
		t.Fatal("unchanged read released an uncertain operation")
	}
	r.Action = "apply"
	s.Handle(context.Background(), r)
	if f.calls != 0 {
		t.Fatal("uncertain claim replayed")
	}
	op, _, e = s.Journal.Get(context.Background(), r.ID)
	if e != nil || op.State != "reconciliation_required" {
		t.Fatal("uncertain target unlocked")
	}
}

func TestSambaStage1(t *testing.T) {
	path := os.Getenv("IDENTITY_AD_PROFILE_LAB")
	if path == "" {
		t.Skip("isolated Samba fixture not configured")
	}
	if path != "/tmp/lab-config.json" {
		t.Fatal("laboratory-only fixture required")
	}
	var lab struct {
		Config   Config
		Targets  map[string]string
		Password string
	}
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &lab) != nil {
		t.Fatal("fixture unavailable")
	}
	if lab.Config.URL != "ldaps://dc1.profile.test:636" || lab.Config.BaseDN != "DC=profile,DC=test" {
		t.Fatal("synthetic domain guard")
	}
	d, e := NewLDAP(lab.Config)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	actor, e := d.Authenticate(ctx, "operator", lab.Password)
	if e != nil {
		c, err := d.connect(ctx)
		if err != nil {
			t.Fatal("verified TLS/writer bind rejected")
		}
		defer c.Close()
		root, err := one(c, "", ldap.ScopeBaseObject, "(objectClass=*)", []string{"supportedControl", "defaultNamingContext", "dsServiceName"})
		if err != nil {
			t.Fatal("RootDSE rejected")
		}
		t.Logf("assertion advertised=%v", contains(root.GetAttributeValues("supportedControl"), assertionOID))
		domain, err := one(c, d.Config.BaseDN, ldap.ScopeBaseObject, "(objectClass=domain)", []string{"objectGUID", "objectSid"})
		if err != nil {
			t.Fatal("domain read rejected")
		}
		t.Logf("domain GUID/SID match=%v/%v", rawGUID(domain) == d.Config.DomainGUID, sid(domain.GetRawAttributeValue("objectSid")) == d.Config.DomainSID)
		dc, err := one(c, root.GetAttributeValue("dsServiceName"), ldap.ScopeBaseObject, "(objectClass=*)", []string{"invocationId"})
		if err != nil {
			t.Fatal("DC read rejected")
		}
		t.Logf("DC identity match=%v", hex.EncodeToString(dc.GetRawAttributeValue("invocationId")) == d.Config.DCIdentity)
		a, err := one(c, d.Config.BaseDN, ldap.ScopeWholeSubtree, "(sAMAccountName=operator)", []string{"userAccountControl", "objectSid"})
		if err != nil {
			t.Fatal("actor search failed")
		}
		t.Logf("actor UAC=%s", a.GetAttributeValue("userAccountControl"))
		g, err := one(c, d.Config.OperatorGroupDN, ldap.ScopeBaseObject, "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(a.DN)+"))", []string{"objectGUID"})
		t.Logf("operator membership lookup ok=%v", err == nil)
		if err == nil {
			t.Logf("operator group GUID match=%v", rawGUID(g) == d.Config.OperatorGroupGUID)
		}
		t.Fatal("operator authentication/capability rejected")
	}
	bad := *d
	bad.roots = x509.NewCertPool()
	if c, err := bad.connect(ctx); err == nil {
		c.Close()
		t.Fatal("untrusted CA accepted")
	}
	bad = *d
	bad.Config.URL = "ldaps://127.0.0.1:636"
	if c, err := bad.connect(ctx); err == nil {
		c.Close()
		t.Fatal("wrong certificate name accepted")
	}
	if _, e = d.Authenticate(ctx, "ordinary", lab.Password); e == nil {
		t.Fatal("nonoperator authorized")
	}
	for _, name := range []string{"privileged", "nested", "outside"} {
		if _, e = d.Read(ctx, lab.Targets[name], actor); e == nil {
			t.Fatalf("unsafe target %s accepted", name)
		}
	}
	before, e := d.Read(ctx, lab.Targets["ordinary"], actor)
	if e != nil {
		t.Fatal("ordinary read rejected")
	}
	if _, err := d.Read(ctx, before.GUID, before.SID); err == nil {
		t.Fatal("self modification accepted")
	}
	if d.Ready(ctx) != nil {
		// This Samba build lacks RFC4528. The production adapter must refuse,
		// never replace CAS with an unconditional operation.
		if d.Modify(ctx, actor, before, Values{"displayName": {"must not write"}}) != ErrDenied {
			t.Fatal("missing CAS was bypassed")
		}
		got, err := d.Read(ctx, before.GUID, actor)
		if err != nil || !reflect.DeepEqual(got, before) {
			t.Fatal("blocked write changed target")
		}
		s, _ := fixture(t)
		s.Directory = d
		s.Policy = d.Config.Revision
		if _, err = s.Handle(ctx, Request{Action: "prepare", Username: "operator", Password: lab.Password, ID: testID, Target: before.GUID, Changes: Values{"displayName": {"blocked"}}}); err == nil {
			t.Fatal("unsupported backend accepted plan")
		}
		var operations int
		s.Journal.DB.QueryRow(`SELECT count(*) FROM ad_profile_operations`).Scan(&operations)
		if operations != 0 {
			t.Fatal("unsupported backend queued write")
		}
		c, err := d.connect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// Separate fixture-only ACL exercise, NOT a runtime fallback or service acceptance.
		req := ldap.NewModifyRequest(before.DN, nil)
		req.Replace("displayName", []string{"Fixture ACL After"})
		if c.Modify(req) != nil {
			t.Fatal("delegated attribute ACL failed")
		}
		restore := ldap.NewModifyRequest(before.DN, nil)
		restore.Replace("displayName", before.Values["displayName"])
		if c.Modify(restore) != nil {
			t.Fatal("fixture rollback failed")
		}
		final, err := d.Read(ctx, before.GUID, actor)
		if err != nil || !reflect.DeepEqual(final.Values, before.Values) {
			t.Fatal("fixture rollback not exact")
		}
		for _, attr := range []string{"description", "userAccountControl", "servicePrincipalName"} {
			if c.Modify(ldapModify(before.DN, attr)) == nil {
				t.Fatalf("ACL allowed %s", attr)
			}
		}
		outside, err := one(c, d.Config.BaseDN, ldap.ScopeWholeSubtree, guidFilter(lab.Targets["outside"]), []string{"objectGUID"})
		if err != nil {
			t.Fatal(err)
		}
		deny := ldap.NewModifyRequest(outside.DN, nil)
		deny.Replace("displayName", []string{"forbidden"})
		if c.Modify(deny) == nil {
			t.Fatal("outside ACL allowed write")
		}
		t.Log("Samba: TLS, roles, protected/nested/outside guards, missing-CAS denial and separate fixture ACL/rollback passed; production positive CAS acceptance BLOCKED")
		testSambaExecutorProcess(t, lab.Config, lab.Password, before.GUID)
		return
	}
	// Real LDAP CAS and attribute ACLs, not a stubbed server.
	if e = d.Modify(ctx, actor, before, Values{"displayName": {"Lab After"}}); e != nil {
		t.Fatal("allowed modify failed", e)
	}
	if e = d.Modify(ctx, actor, before, Values{"displayName": {"stale overwrite"}}); e != ErrDenied {
		t.Fatal("stale critical assertion not rejected")
	}
	current, e := d.Read(ctx, before.GUID, actor)
	if e != nil || current.Values["displayName"][0] != "Lab After" {
		t.Fatal("readback failed")
	}
	if e = d.Modify(ctx, actor, current, Values{"displayName": before.Values["displayName"]}); e != nil {
		t.Fatal("real compensation failed")
	}
	restored, e := d.Read(ctx, before.GUID, actor)
	if e != nil || !reflect.DeepEqual(restored.Values, before.Values) {
		t.Fatal("exact attribute rollback failed")
	}
	c, e := d.connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	for _, attr := range []string{"description", "userAccountControl", "servicePrincipalName"} {
		req := ldapModify(before.DN, attr)
		if err := c.Modify(req); err == nil {
			t.Fatalf("least-privilege ACL allowed %s", attr)
		}
	}
	// Exercise the durable production service against the real DC, including a bound inverse plan.
	s, _ := fixture(t)
	s.Directory = d
	s.Policy = lab.Config.Revision
	request := Request{Action: "prepare", Username: "operator", Password: lab.Password, ID: testID, Target: before.GUID, Changes: Values{"displayName": {"Service After"}}}
	if _, e = s.Handle(ctx, request); e != nil {
		t.Fatal("real service prepare failed")
	}
	request.Action = "apply"
	response, e := s.Handle(ctx, request)
	if e != nil || response.Operation.State != "succeeded" {
		t.Fatal("real service apply failed", e)
	}
	request = Request{Action: "prepare", Username: "operator", Password: lab.Password, ID: strings.Repeat("4", 32), Target: before.GUID, Changes: Values{"displayName": before.Values["displayName"]}, Parent: testID}
	if _, e = s.Handle(ctx, request); e != nil {
		t.Fatal("bound inverse prepare failed", e)
	}
	request.Action = "apply"
	if _, e = s.Handle(ctx, request); e != nil {
		t.Fatal("bound inverse failed")
	}
	final, e := d.Read(ctx, before.GUID, actor)
	if e != nil || !reflect.DeepEqual(final.Values, before.Values) {
		t.Fatal("service rollback not exact")
	}
	fmt.Println("Samba stage1: verified TLS, role/target guards, critical stale CAS, attribute ACL negatives, durable apply and exact compensation passed")
}
