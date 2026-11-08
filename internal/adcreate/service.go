// Package adcreate implements the disabled-user planning contract. No production
// directory adapter or enabled backend is installed by the application.
package adcreate

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	_ "modernc.org/sqlite"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrDenied = errors.New("create denied")
var ErrUncertain = errors.New("create outcome uncertain")
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,19}$`)
var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Input struct {
	Name        string
	DisplayName string
}
type Scope struct {
	Domain, DC, OU, Policy, UPNSuffix string
	Epoch                             uint64 `json:",omitempty"`
}
type Plan struct {
	ID, Actor string
	Scope     Scope
	Input     Input
	Expires   int64
	Digest    string
}
type Result struct{ GUID, SID, Version string }
type Wire struct {
	Bytes   []byte
	Expires int64
}
type BoundRequest struct {
	Plan       Plan
	Wire       Wire
	WireDigest string
}
type Operation struct {
	Plan     Plan
	State    string
	Result   Result
	Evidence *Result // read-only receipt observation, never changes operation state
}
type Event struct {
	Event string
	At    int64
}

// Operations permits a separate executor transport without putting AD writer
// credentials into the web server. No production transport is installed here.
// IsEnabled must be a local configuration read, never an executor/network call.
type Operations interface {
	IsEnabled() bool
	Prepare(context.Context, string, string, Input) (Operation, error)
	Action(context.Context, string, string, string, string, string) (Operation, error)
	History(context.Context, string, string, string) ([]Event, error)
}

func (s *Service) IsEnabled() bool { return s != nil && s.Enabled }

// Ready must reject unsupported/unproved directory semantics. Production has
// no implementation. Authentication includes a fresh role/account check.
type Directory interface {
	Ready(context.Context) error
	Authenticate(context.Context, string, string) (string, error)
	Available(context.Context, Scope, Input) error
	Authorize(context.Context, string, Scope) error
	Encode(context.Context, Plan) (Wire, error)
	Create(context.Context, BoundRequest) (Result, error)
	Receipt(context.Context, BoundRequest) (Result, error)
}
type Service struct {
	Enabled        bool
	RecoveryOnly   bool // Restored snapshots support inspection, never dispatch.
	Scope          Scope
	Directory      Directory
	db             *sql.DB
	aead           cipher.AEAD
	reservationKey []byte
	mu             sync.Mutex
	attempts       map[string][]time.Time
}

// Schema is explicitly initialized only in a private offline journal, not on
// application startup. Each name stays reserved through success or uncertainty.
const Schema = `CREATE TABLE create_ops(id TEXT PRIMARY KEY,actor TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('prepared','applying','uncertain','succeeded','cancelled','expired')),payload BLOB NOT NULL,result BLOB);
CREATE UNIQUE INDEX create_one_dispatch ON create_ops((1)) WHERE state IN ('applying','uncertain');
CREATE TABLE create_names(name TEXT PRIMARY KEY,id TEXT NOT NULL);
CREATE TABLE create_dispatch(id TEXT PRIMARY KEY,plan_digest TEXT NOT NULL,wire_digest TEXT NOT NULL,payload BLOB NOT NULL);
CREATE TABLE create_audit(id TEXT NOT NULL,actor TEXT NOT NULL,event TEXT NOT NULL,at BIGINT NOT NULL);`

func New(db *sql.DB, key []byte, scope Scope, d Directory) (*Service, error) {
	if db == nil || len(key) != 32 || scope.Domain == "" || scope.DC == "" || scope.OU == "" || scope.Policy == "" || scope.UPNSuffix == "" || strings.ContainsAny(scope.UPNSuffix, "@/\\ \t\r\n") || d == nil {
		return nil, ErrDenied
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	r := hmac.New(sha256.New, key)
	r.Write([]byte("identity-create-name-reservation-v1"))
	return &Service{Scope: scope, Directory: d, db: db, aead: a, reservationKey: r.Sum(nil), attempts: map[string][]time.Time{}}, nil
}
func digest(p Plan) string {
	p.Digest = ""
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validInput(i Input) bool {
	if !namePattern.MatchString(i.Name) || strings.TrimSpace(i.DisplayName) != i.DisplayName || len(i.DisplayName) == 0 || len(i.DisplayName) > 256 {
		return false
	}
	for _, b := range []byte(i.DisplayName) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
func (s *Service) seal(id string, value any) ([]byte, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	n := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return s.aead.Seal(n, n, b, []byte(id)), nil
}
func (s *Service) open(id string, b []byte, v any) error {
	n := s.aead.NonceSize()
	if len(b) < n {
		return ErrDenied
	}
	p, e := s.aead.Open(nil, b[:n], b[n:], []byte(id))
	if e != nil {
		return ErrDenied
	}
	if json.Unmarshal(p, v) != nil {
		return ErrDenied
	}
	return nil
}
func (s *Service) authenticate(ctx context.Context, user, password string) (string, error) {
	if !s.Enabled || s.Directory == nil || len(password) == 0 || len(password) > 1024 || len(user) == 0 || len(user) > 64 {
		return "", ErrDenied
	}
	now := time.Now()
	times := s.attempts["global"]
	kept := times[:0]
	for _, t := range times {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 20 {
		return "", ErrDenied
	}
	s.attempts["global"] = append(kept, now)
	// All calls hold mu; a single service has bounded authentication work.
	if e := s.Directory.Ready(ctx); e != nil {
		return "", ErrDenied
	}
	actor, e := s.Directory.Authenticate(ctx, user, password)
	if e != nil || actor == "" {
		if !s.RecoveryOnly {
			_, _ = s.db.ExecContext(ctx, `INSERT INTO create_audit VALUES('','','auth_denied',?)`, time.Now().Unix())
		}
		return "", ErrDenied
	}
	if s.Directory.Authorize(ctx, actor, s.Scope) != nil {
		return "", ErrDenied
	}
	return actor, nil
}
func (s *Service) Prepare(ctx context.Context, user, password string, input Input) (Operation, error) {
	return s.prepare(ctx, user, password, input, "")
}

// PrepareWithID binds a caller-generated correlation ID before the transport
// sends anything. Repeated/conflicting IDs are denied, never dispatched again.
func (s *Service) PrepareWithID(ctx context.Context, user, password, id string, input Input) (Operation, error) {
	if !idPattern.MatchString(id) || id == strings.Repeat("0", 32) {
		return Operation{}, ErrDenied
	}
	return s.prepare(ctx, user, password, input, id)
}
func (s *Service) prepare(ctx context.Context, user, password string, input Input, planID string) (Operation, error) {
	if s.RecoveryOnly {
		return Operation{}, ErrDenied
	}
	if !s.mu.TryLock() {
		return Operation{}, ErrDenied
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	actor, e := s.authenticate(ctx, user, password)
	if e != nil || !validInput(input) {
		return Operation{}, ErrDenied
	}
	now := time.Now()
	if s.Directory.Available(ctx, s.Scope, input) != nil {
		return Operation{}, ErrDenied
	}
	if planID == "" {
		id := make([]byte, 16)
		if _, e = rand.Read(id); e != nil {
			return Operation{}, e
		}
		planID = hex.EncodeToString(id)
	}
	p := Plan{ID: planID, Actor: actor, Scope: s.Scope, Input: input, Expires: now.Unix() + 300}
	p.Digest = digest(p)
	payload, e := s.seal(p.ID, p)
	if e != nil {
		return Operation{}, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Operation{}, e
	}
	defer tx.Rollback()
	var recent int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM create_audit WHERE actor=? AND event='prepared' AND at>?`, actor, now.Unix()-3600).Scan(&recent); e != nil || recent >= 5 {
		return Operation{}, ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO create_ops VALUES(?,?,'prepared',?,NULL)`, p.ID, actor, payload); e != nil {
		return Operation{}, ErrDenied
	}
	for _, name := range []string{"sam:" + s.Scope.Domain + ":" + input.Name, "upn:" + input.Name + "@" + s.Scope.UPNSuffix} {
		h := hmac.New(sha256.New, s.reservationKey)
		h.Write([]byte(name))
		if _, e = tx.ExecContext(ctx, `INSERT INTO create_names VALUES(?,?)`, hex.EncodeToString(h.Sum(nil)), p.ID); e != nil {
			return Operation{}, ErrDenied
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO create_audit VALUES(?,?,'prepared',?)`, p.ID, actor, now.Unix()); e != nil {
		return Operation{}, ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return Operation{}, e
	}
	return Operation{Plan: p, State: "prepared"}, nil
}
func (s *Service) get(ctx context.Context, id, actor string) (Operation, error) {
	var o Operation
	var owner string
	var b, r []byte
	if !idPattern.MatchString(id) {
		return o, ErrDenied
	}
	if s.db.QueryRowContext(ctx, `SELECT actor,state,payload,result FROM create_ops WHERE id=?`, id).Scan(&owner, &o.State, &b, &r) != nil || owner != actor {
		return o, ErrDenied
	}
	if len(b) == 0 && len(r) == 0 && (o.State == "succeeded" || o.State == "cancelled" || o.State == "expired") {
		o.Plan.ID = id
		return o, nil
	}
	if s.open(id, b, &o.Plan) != nil || o.Plan.ID != id || o.Plan.Actor != actor || o.Plan.Digest != digest(o.Plan) || !validInput(o.Plan.Input) {
		return Operation{}, ErrDenied
	}
	if o.Plan.Scope != s.Scope {
		prior := o.Plan.Scope
		if prior.Epoch == 0 || prior.Epoch >= s.Scope.Epoch ||
			(o.State != "succeeded" && o.State != "cancelled" && o.State != "expired") {
			return Operation{}, ErrDenied
		}
		prior.DC, prior.Epoch = s.Scope.DC, s.Scope.Epoch
		if prior != s.Scope {
			return Operation{}, ErrDenied
		}
	}
	if len(r) > 0 && s.open(id+":result", r, &o.Result) != nil {
		return Operation{}, ErrDenied
	}
	return o, nil
}
func (s *Service) transition(ctx context.Context, id, actor, from, to string, result []byte) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE create_ops SET state=?,result=? WHERE id=? AND actor=? AND state=?`, to, result, id, actor, from)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return ErrDenied
	}
	if to == "cancelled" || to == "expired" {
		if _, e = tx.ExecContext(ctx, `DELETE FROM create_names WHERE id=?`, id); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO create_audit VALUES(?,?,?,?)`, id, actor, to, time.Now().Unix()); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Service) Action(ctx context.Context, user, password, id, action, confirmation string) (Operation, error) {
	if s.RecoveryOnly && action != "status" && action != "evidence" {
		return Operation{}, ErrDenied
	}
	if !s.mu.TryLock() {
		return Operation{}, ErrDenied
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	actor, e := s.authenticate(ctx, user, password)
	if e != nil {
		return Operation{}, e
	}
	o, e := s.get(ctx, id, actor)
	if e != nil {
		return Operation{}, e
	}
	if action == "status" {
		return o, nil
	}
	if action == "evidence" {
		if o.Plan.Scope != s.Scope {
			return o, ErrDenied
		}
		if o.State != "applying" && o.State != "uncertain" && o.State != "succeeded" {
			return o, ErrDenied
		}
		b, e := s.binding(ctx, o.Plan)
		if e != nil {
			return o, ErrUncertain
		}
		r, e := s.Directory.Receipt(ctx, b)
		if e != nil || !validResult(r) || (o.State == "succeeded" && r != o.Result) {
			return o, ErrUncertain
		}
		o.Evidence = &r
		return o, nil
	}
	if o.State != "prepared" {
		_, _ = s.db.ExecContext(ctx, `INSERT INTO create_audit VALUES(?,?,'denied',?)`, id, actor, time.Now().Unix())
		return o, ErrDenied
	}
	if o.Plan.Expires <= time.Now().Unix() {
		e = s.transition(ctx, id, actor, "prepared", "expired", nil)
		o.State = "expired"
		return o, e
	}
	if action == "cancel" {
		e = s.transition(ctx, id, actor, "prepared", "cancelled", nil)
		o.State = "cancelled"
		return o, e
	}
	if action != "confirm" || confirmation != o.Plan.Digest {
		_, _ = s.db.ExecContext(ctx, `INSERT INTO create_audit VALUES(?,?,'denied',?)`, id, actor, time.Now().Unix())
		return o, ErrDenied
	}
	if s.Directory.Available(ctx, s.Scope, o.Plan.Input) != nil {
		return o, ErrDenied
	}
	wire, e := s.Directory.Encode(ctx, o.Plan)
	if e != nil {
		return o, ErrDenied
	}
	bound := BoundRequest{Plan: o.Plan, Wire: wire}
	sum := sha256.Sum256(wire.Bytes)
	bound.WireDigest = hex.EncodeToString(sum[:])
	if !validBinding(bound, o.Plan, time.Now().Unix(), true) || s.Directory.Authorize(ctx, actor, s.Scope) != nil {
		return o, ErrDenied
	}
	if s.bindAndClaim(ctx, bound) != nil {
		return o, ErrDenied
	}
	o.State = "uncertain"
	// Reload the committed ciphertext instead of dispatching the in-memory projection.
	bound, e = s.binding(ctx, o.Plan)
	var result Result
	if e == nil && s.Directory.Authorize(ctx, actor, s.Scope) == nil {
		result, e = s.Directory.Create(ctx, bound)
	} else {
		e = ErrDenied
	}
	if e != nil || !validResult(result) {
		// Even a backend error can follow a committed Add. Never infer no-effect.
		failureCtx, cancelFailure := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancelFailure()
		_ = s.transition(failureCtx, id, actor, "applying", "uncertain", nil)
		return o, ErrUncertain
	}
	payload, e := s.seal(id+":result", result)
	if e != nil {
		return o, ErrUncertain
	}
	if s.transition(ctx, id, actor, "applying", "succeeded", payload) != nil {
		return o, ErrUncertain
	}
	o.State = "succeeded"
	o.Result = result
	return o, nil
}
func validResult(result Result) bool {
	version, e := strconv.ParseUint(result.Version, 10, 64)
	return idPattern.MatchString(result.GUID) && result.GUID != strings.Repeat("0", 32) && strings.HasPrefix(result.SID, "S-1-5-21-") && e == nil && version > 0 && strconv.FormatUint(version, 10) == result.Version
}

func validBinding(b BoundRequest, p Plan, now int64, fresh bool) bool {
	sum := sha256.Sum256(b.Wire.Bytes)
	return b.Plan == p && p.Digest == digest(p) && len(b.Wire.Bytes) > 0 && len(b.Wire.Bytes) <= 1024 &&
		b.WireDigest == hex.EncodeToString(sum[:]) && b.Wire.Expires <= p.Expires && b.Wire.Expires > 0 && (!fresh || (b.Wire.Expires > now && b.Wire.Expires <= now+60))
}
func (s *Service) bindAndClaim(ctx context.Context, b BoundRequest) error {
	payload, e := s.seal(b.Plan.ID+":dispatch", b)
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE create_ops SET state='applying' WHERE id=? AND actor=? AND state='prepared'`, b.Plan.ID, b.Plan.Actor)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO create_dispatch VALUES(?,?,?,?)`, b.Plan.ID, b.Plan.Digest, b.WireDigest, payload); e != nil {
		return e
	}
	for _, event := range []string{"dispatch_bound", "applying"} {
		if _, e = tx.ExecContext(ctx, `INSERT INTO create_audit VALUES(?,?,?,?)`, b.Plan.ID, b.Plan.Actor, event, time.Now().Unix()); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Service) binding(ctx context.Context, p Plan) (BoundRequest, error) {
	var b BoundRequest
	var plan, wire string
	var payload []byte
	if s.db.QueryRowContext(ctx, `SELECT plan_digest,wire_digest,payload FROM create_dispatch WHERE id=?`, p.ID).Scan(&plan, &wire, &payload) != nil || s.open(p.ID+":dispatch", payload, &b) != nil || plan != p.Digest || wire != b.WireDigest || !validBinding(b, p, 0, false) {
		return BoundRequest{}, ErrDenied
	}
	return b, nil
}
func (s *Service) History(ctx context.Context, user, password, id string) ([]Event, error) {
	if !s.mu.TryLock() {
		return nil, ErrDenied
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	actor, e := s.authenticate(ctx, user, password)
	if e != nil {
		return nil, e
	}
	if _, e = s.get(ctx, id, actor); e != nil {
		return nil, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT event,at FROM create_audit WHERE id=? ORDER BY rowid LIMIT 100`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var event Event
		if e = rows.Scan(&event.Event, &event.At); e != nil {
			return nil, e
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
