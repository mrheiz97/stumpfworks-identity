package adcreate

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureDirectory struct {
	sends          int
	deny           bool
	after          func() error
	mu             sync.Mutex
	authorizations atomic.Int32
	authorizeHook  func(int) error
	receipts       int
}

func (d *fixtureDirectory) Ready(context.Context) error {
	if d.deny {
		return ErrDenied
	}
	return nil
}
func (d *fixtureDirectory) Authenticate(_ context.Context, user, password string) (string, error) {
	if password != "secret" || user != "operator" || d.deny {
		return "", ErrDenied
	}
	return "actor", nil
}
func (d *fixtureDirectory) Available(context.Context, Scope, Input) error { return nil }
func (d *fixtureDirectory) Authorize(context.Context, string, Scope) error {
	call := int(d.authorizations.Add(1))
	if d.authorizeHook != nil {
		if e := d.authorizeHook(call); e != nil {
			return e
		}
	}
	if d.deny {
		return ErrDenied
	}
	return nil
}
func (d *fixtureDirectory) Encode(_ context.Context, p Plan) (Wire, error) {
	return Wire{Bytes: []byte(p.Digest), Expires: time.Now().Unix() + 60}, nil
}
func (d *fixtureDirectory) Receipt(context.Context, BoundRequest) (Result, error) {
	d.receipts++
	return Result{GUID: strings.Repeat("a", 32), SID: "S-1-5-21-1-2-3-1000", Version: "42"}, nil
}

func TestDurableDispatchAndReadOnlyEvidence(t *testing.T) {
	s, d := setup(t)
	o := prepare(t, s)
	d.after = func() error {
		b, e := s.binding(context.Background(), o.Plan)
		if e != nil || len(b.Wire.Bytes) == 0 {
			t.Fatal("send before durable binding")
		}
		var state string
		s.db.QueryRow(`SELECT state FROM create_ops WHERE id=?`, o.Plan.ID).Scan(&state)
		if state != "applying" {
			t.Fatal("send before claim")
		}
		return ErrUncertain
	}
	if _, e := confirm(s, o); !errors.Is(e, ErrUncertain) {
		t.Fatal("loss")
	}
	fresh := &fixtureDirectory{}
	reopened, e := New(s.db, []byte(strings.Repeat("k", 32)), s.Scope, fresh)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Enabled = true
	evidence, e := reopened.Action(context.Background(), "operator", "secret", o.Plan.ID, "evidence", "")
	if e != nil || evidence.Evidence == nil || evidence.State != "uncertain" || evidence.Result.GUID != "" || fresh.sends != 0 || fresh.receipts != 1 {
		t.Fatal("receipt unlocked or replayed", e)
	}
	if _, e = confirm(reopened, o); e == nil || fresh.sends != 0 {
		t.Fatal("replay after receipt")
	}
	for _, mutation := range []string{`UPDATE create_dispatch SET plan_digest='wrong'`, `UPDATE create_dispatch SET wire_digest='wrong'`, `UPDATE create_dispatch SET payload=x'01'`} {
		var plan, wire string
		var payload []byte
		s.db.QueryRow(`SELECT plan_digest,wire_digest,payload FROM create_dispatch`).Scan(&plan, &wire, &payload)
		if _, e = s.db.Exec(mutation); e != nil {
			t.Fatal(e)
		}
		calls := fresh.receipts
		if _, e = reopened.Action(context.Background(), "operator", "secret", o.Plan.ID, "evidence", ""); e == nil || fresh.receipts != calls {
			t.Fatal("corrupt dispatch accepted")
		}
		s.db.Exec(`UPDATE create_dispatch SET plan_digest=?,wire_digest=?,payload=?`, plan, wire, payload)
	}
}
func TestRoleRevokedDuringDispatchPreparation(t *testing.T) {
	for _, revokeAt := range []int{3, 4} {
		t.Run(strconv.Itoa(revokeAt), func(t *testing.T) {
			s, d := setup(t)
			o := prepare(t, s)
			d.authorizeHook = func(call int) error {
				if call >= revokeAt {
					return ErrDenied
				}
				return nil
			}
			if _, e := confirm(s, o); e == nil || d.sends != 0 {
				t.Fatal("revoked role sent")
			}
			var count int
			s.db.QueryRow(`SELECT COUNT(*) FROM create_dispatch`).Scan(&count)
			if (revokeAt == 3 && count != 0) || (revokeAt == 4 && count != 1) {
				t.Fatal("incorrect durable boundary")
			}
		})
	}
}
func TestBindingAuditFailurePreventsSend(t *testing.T) {
	s, d := setup(t)
	o := prepare(t, s)
	if _, e := s.db.Exec(`CREATE TRIGGER fail_binding BEFORE INSERT ON create_audit WHEN NEW.event='dispatch_bound' BEGIN SELECT RAISE(ABORT,'test'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e := confirm(s, o); e == nil || d.sends != 0 {
		t.Fatal("binding audit bypass")
	}
	var state string
	var count int
	s.db.QueryRow(`SELECT state FROM create_ops`).Scan(&state)
	s.db.QueryRow(`SELECT COUNT(*) FROM create_dispatch`).Scan(&count)
	if state != "prepared" || count != 0 {
		t.Fatal("partial binding transaction")
	}
}
func TestPrepareCorrelationIDIsDurableAndNotReused(t *testing.T) {
	s, d := setup(t)
	id := strings.Repeat("c", 32)
	i := Input{Name: "newuser", DisplayName: "New User"}
	plan, e := s.PrepareWithID(context.Background(), "operator", "secret", id, i)
	if e != nil || plan.Plan.ID != id {
		t.Fatal("correlation not preserved")
	}
	if _, e = s.PrepareWithID(context.Background(), "operator", "secret", id, Input{Name: "other", DisplayName: "Other"}); e == nil || d.sends != 0 {
		t.Fatal("conflicting correlation adopted")
	}
	got, e := s.Action(context.Background(), "operator", "secret", id, "status", "")
	if e != nil || got.Plan.Input != i || got.State != "prepared" {
		t.Fatal("cannot inspect original after lost prepare response")
	}
}
func (d *fixtureDirectory) Create(context.Context, BoundRequest) (Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sends++
	if d.after != nil {
		if e := d.after(); e != nil {
			return Result{}, e
		}
	}
	return Result{GUID: strings.Repeat("a", 32), SID: "S-1-5-21-1-2-3-1000", Version: "42"}, nil
}
func setup(t *testing.T) (*Service, *fixtureDirectory) {
	t.Helper()
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), "journal.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	if _, e = db.Exec(Schema); e != nil {
		t.Fatal(e)
	}
	d := &fixtureDirectory{}
	s, e := New(db, []byte(strings.Repeat("k", 32)), Scope{Domain: "domain", DC: "dc", OU: "ou", Policy: "v1", UPNSuffix: "profile.test"}, d)
	if e != nil {
		t.Fatal(e)
	}
	s.Enabled = true
	return s, d
}
func prepare(t *testing.T, s *Service) Operation {
	t.Helper()
	o, e := s.Prepare(context.Background(), "operator", "secret", Input{Name: "newuser", DisplayName: "New User"})
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func confirm(s *Service, o Operation) (Operation, error) {
	return s.Action(context.Background(), "operator", "secret", o.Plan.ID, "confirm", o.Plan.Digest)
}
func TestPlanConfirmAuditAndPrivacy(t *testing.T) {
	s, d := setup(t)
	o := prepare(t, s)
	if d.sends != 0 {
		t.Fatal("prepare wrote")
	}
	if _, e := s.Action(context.Background(), "operator", "secret", o.Plan.ID, "confirm", "wrong"); e == nil {
		t.Fatal("digest")
	}
	done, e := confirm(s, o)
	if e != nil || done.State != "succeeded" || d.sends != 1 {
		t.Fatal("confirm", e)
	}
	if _, e = confirm(s, o); e == nil || d.sends != 1 {
		t.Fatal("replay")
	}
	events, e := s.History(context.Background(), "operator", "secret", o.Plan.ID)
	if e != nil || len(events) != 6 || events[0].Event != "prepared" || events[1].Event != "denied" || events[2].Event != "dispatch_bound" || events[3].Event != "applying" || events[4].Event != "succeeded" {
		t.Fatal("audit")
	}
	var payload []byte
	s.db.QueryRow(`SELECT payload FROM create_ops`).Scan(&payload)
	if strings.Contains(string(payload), "newuser") || strings.Contains(string(payload), "New User") {
		t.Fatal("plaintext plan")
	}
	var token string
	s.db.QueryRow(`SELECT name FROM create_names LIMIT 1`).Scan(&token)
	if strings.Contains(token, "newuser") {
		t.Fatal("plaintext reservation")
	}
}
func TestProtectionGates(t *testing.T) {
	for _, c := range []string{"disabled", "capability", "role", "expired", "tampered", "scope", "wrongactor", "cancel"} {
		t.Run(c, func(t *testing.T) {
			s, d := setup(t)
			o := prepare(t, s)
			switch c {
			case "disabled":
				s.Enabled = false
			case "capability", "role":
				d.deny = true
			case "expired":
				o.Plan.Expires = 1
				o.Plan.Digest = digest(o.Plan)
				b, _ := s.seal(o.Plan.ID, o.Plan)
				s.db.Exec(`UPDATE create_ops SET payload=?`, b)
			case "tampered":
				s.db.Exec(`UPDATE create_ops SET payload=x'01'`)
			case "scope":
				s.Scope.Policy = "other"
			case "wrongactor":
				s.db.Exec(`UPDATE create_ops SET actor='other'`)
			case "cancel":
				if _, e := s.Action(context.Background(), "operator", "secret", o.Plan.ID, "cancel", ""); e != nil {
					t.Fatal(e)
				}
			}
			_, e := confirm(s, o)
			if d.sends != 0 {
				t.Fatal("unsafe send")
			}
			if e == nil && c != "expired" {
				t.Fatal("accepted")
			}
		})
	}
	for _, i := range []Input{{Name: "../escape", DisplayName: "Name"}, {Name: "NewUser", DisplayName: "Name"}, {Name: "user$", DisplayName: "Name"}, {Name: "user", DisplayName: "\n"}, {Name: "user", DisplayName: "Müller"}} {
		s, _ := setup(t)
		if _, e := s.Prepare(context.Background(), "operator", "secret", i); e == nil {
			t.Fatal("invalid input")
		}
	}
}
func TestUncertaintyRestartReservationAndAuditFailure(t *testing.T) {
	for _, phase := range []string{"prepare", "applying", "succeeded", "reply"} {
		t.Run(phase, func(t *testing.T) {
			s, d := setup(t)
			if phase == "prepare" {
				s.db.Exec(`CREATE TRIGGER fail BEFORE INSERT ON create_audit BEGIN SELECT RAISE(ABORT,'test'); END`)
				if _, e := s.Prepare(context.Background(), "operator", "secret", Input{Name: "newuser", DisplayName: "New User"}); e == nil || d.sends != 0 {
					t.Fatal("prepare audit bypass")
				}
				return
			}
			o := prepare(t, s)
			if phase == "reply" {
				d.after = func() error { return errors.New("lost reply") }
			} else {
				s.db.Exec(`CREATE TRIGGER fail BEFORE INSERT ON create_audit WHEN NEW.event='` + phase + `' BEGIN SELECT RAISE(ABORT,'test'); END`)
			}
			_, e := confirm(s, o)
			if e == nil {
				t.Fatal("failure hidden")
			}
			if phase == "applying" {
				if d.sends != 0 {
					t.Fatal("claim audit bypass")
				}
				return
			}
			reopened, e := New(s.db, []byte(strings.Repeat("k", 32)), s.Scope, d)
			if e != nil {
				t.Fatal(e)
			}
			reopened.Enabled = true
			if _, e = confirm(reopened, o); e == nil || d.sends != 1 {
				t.Fatal("replayed after restart")
			}
			if _, e = reopened.Prepare(context.Background(), "operator", "secret", o.Plan.Input); e == nil {
				t.Fatal("name reservation lost")
			}
		})
	}
}
func TestConcurrentClaimAndCancellation(t *testing.T) {
	s, d := setup(t)
	o := prepare(t, s)
	other, _ := New(s.db, []byte(strings.Repeat("k", 32)), s.Scope, d)
	other.Enabled = true
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); confirm(s, o) }()
	go func() {
		defer wg.Done()
		other.Action(context.Background(), "operator", "secret", o.Plan.ID, "cancel", "")
	}()
	wg.Wait()
	result, e := s.Action(context.Background(), "operator", "secret", o.Plan.ID, "status", "")
	if e != nil {
		t.Fatal(e)
	}
	if !((result.State == "cancelled" && d.sends == 0) || (result.State == "succeeded" && d.sends == 1)) {
		t.Fatal("claim/cancel race", result.State, d.sends)
	}
}
func TestHTTPBoundary(t *testing.T) {
	for _, kind := range []string{"no-session", "http", "csrf", "origin", "duplicate", "unknown", "method", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			s, d := setup(t)
			h := Handler{Service: s, Session: func(*http.Request) (string, string, error) { return "operator", "csrf", nil }}
			form := url.Values{"_csrf": {"csrf"}, "action": {"prepare"}, "password": {"secret"}, "name": {"newuser"}, "display": {"New User"}}
			method := "POST"
			address := "https://identity.test/create"
			switch kind {
			case "no-session":
				h.Session = nil
			case "http":
				address = "http://identity.test/create"
			case "csrf":
				form.Set("_csrf", "other")
			case "duplicate":
				form["name"] = []string{"newuser", "other"}
			case "unknown":
				form.Set("uac", "512")
			case "method":
				method = "PUT"
			case "oversize":
				form.Set("display", strings.Repeat("x", 9000))
			}
			req := httptest.NewRequest(method, address, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", "https://identity.test")
			if kind == "origin" {
				req.Header.Set("Origin", "https://evil.test")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code < 400 || d.sends != 0 {
				t.Fatal("HTTP boundary", w.Code)
			}
		})
	}
}
