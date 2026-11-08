package adprofile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Request struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Password string `json:"password"`
	ID       string `json:"id"`
	Target   string `json:"target,omitempty"`
	Changes  Values `json:"changes,omitempty"`
	Parent   string `json:"parent,omitempty"`
}
type Response struct {
	Events    []AuditEvent `json:"events,omitempty"`
	Operation Operation    `json:"operation"`
	Before    Values       `json:"before,omitempty"`
	After     Values       `json:"after,omitempty"`
	Error     string       `json:"error,omitempty"`
}
type Service struct {
	Enabled        bool
	Policy         string
	Directory      Directory
	Journal        *Journal
	mu             sync.Mutex // one global in-flight operation; external writers still require LDAP CAS
	attempts       map[string][]time.Time
	globalAttempts []time.Time
}

func (s *Service) Handle(ctx context.Context, r Request) (response Response, failure error) {
	if !s.Enabled || s.Policy == "" || s.Directory == nil || s.Journal == nil || !idPattern.MatchString(r.ID) {
		return Response{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if !s.mu.TryLock() {
		return Response{}, ErrDenied
	}
	defer s.mu.Unlock()
	actorID := ""
	defer func() {
		if failure != nil {
			auditCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if s.Journal.Denied(auditCtx, r.ID, actorID) != nil && !errors.Is(failure, ErrUncertain) {
				failure = ErrDenied
			}
		}
	}()
	now := time.Now()
	r.Username = strings.ToLower(strings.TrimSpace(r.Username))
	global := []time.Time{}
	for _, v := range s.globalAttempts {
		if now.Sub(v) < time.Minute {
			global = append(global, v)
		}
	}
	if len(global) >= 30 {
		return Response{}, ErrDenied
	}
	s.globalAttempts = append(global, now)
	if s.Journal.Erase(ctx, now) != nil {
		return Response{}, ErrDenied
	}
	if s.attempts == nil {
		s.attempts = map[string][]time.Time{}
	}
	// Bounded per-actor authentication budget, including failed attempts.
	for k, v := range s.attempts {
		if len(v) == 0 || now.Sub(v[len(v)-1]) > 10*time.Minute {
			delete(s.attempts, k)
		}
	}
	if len(s.attempts) >= 1000 {
		return Response{}, ErrDenied
	}
	recent := []time.Time{}
	for _, v := range s.attempts[r.Username] {
		if now.Sub(v) < time.Minute {
			recent = append(recent, v)
		}
	}
	if len(recent) >= 10 {
		return Response{}, ErrDenied
	}
	s.attempts[r.Username] = append(recent, now)
	actor, e := s.Directory.Authenticate(ctx, r.Username, r.Password)
	if e != nil {
		return Response{}, ErrDenied
	}
	actorID = actor
	if r.Action == "rollback-plan" {
		op, p, err := s.Journal.Get(ctx, r.Parent)
		if err != nil || op.Actor != actor || (op.State != "succeeded" && op.State != "reconciled_effect_observed") || len(p.Before.Values) != 4 {
			return Response{}, ErrDenied
		}
		r.Action = "prepare"
		r.Target = p.Target
		r.Changes = clone(p.Before.Values)
	}
	if r.Action == "read" {
		current, err := s.Directory.Read(ctx, r.Target, actor)
		if err != nil {
			return Response{}, ErrDenied
		}
		return Response{Operation: Operation{ID: r.ID, Target: r.Target}, Before: current.Values}, nil
	}
	if r.Action == "prepare" {
		if s.Directory.Ready(ctx) != nil {
			return Response{}, ErrDenied
		}
		if validateValues(r.Changes) != nil || !guidPattern.MatchString(r.Target) {
			return Response{}, ErrDenied
		}
		if existing, p, err := s.Journal.Get(ctx, r.ID); err == nil {
			desired := clone(p.Before.Values)
			for a, v := range r.Changes {
				desired[a] = append([]string(nil), v...)
			}
			if p.Actor != actor || p.Target != r.Target || p.Parent != r.Parent || !reflect.DeepEqual(p.After.Values, desired) {
				return Response{}, ErrDenied
			}
			return Response{Operation: existing, Before: p.Before.Values, After: p.After.Values}, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return Response{}, ErrDenied
		}
		before, e := s.Directory.Read(ctx, r.Target, actor)
		if e != nil {
			return Response{}, ErrDenied
		}
		after := before
		after.Values = clone(before.Values)
		for a, v := range r.Changes {
			after.Values[a] = append([]string(nil), v...)
		}
		if reflect.DeepEqual(before.Values, after.Values) {
			return Response{}, ErrDenied
		}
		if r.Parent != "" {
			op, parent, err := s.Journal.Get(ctx, r.Parent)
			if err != nil || (op.State != "succeeded" && op.State != "reconciled_effect_observed") || parent.Target != r.Target || parent.Actor != actor || !reflect.DeepEqual(before.Values, parent.After.Values) || !reflect.DeepEqual(after.Values, parent.Before.Values) {
				return Response{}, ErrDenied
			}
		}
		p := Plan{ID: r.ID, Actor: actor, Target: r.Target, Policy: s.Policy, Before: before, After: after, Expires: now.Add(5 * time.Minute).Unix(), Parent: r.Parent}
		p.Digest = digest(p)
		if s.Journal.Prepare(ctx, p) != nil {
			return Response{}, ErrDenied
		}
		return Response{Operation: Operation{p.ID, p.Actor, p.Target, "prepared", p.Expires, p.Parent}, Before: before.Values, After: after.Values}, nil
	}
	op, p, e := s.Journal.Get(ctx, r.ID)
	if e != nil || op.Actor != actor {
		return Response{}, ErrDenied
	}
	result := Response{Operation: op}
	switch r.Action {
	case "status":
		result.Events, e = s.Journal.History(ctx, r.ID)
		if e != nil {
			return Response{}, ErrDenied
		}
		return result, nil
	case "cancel":
		if s.Journal.Change(ctx, op, "prepared", "cancelled") != nil {
			return result, ErrDenied
		}
		result.Operation.State = "cancelled"
		return result, nil
	case "reconcile":
		if op.State != "reconciliation_required" {
			return result, ErrDenied
		}
		current, err := s.Directory.Read(ctx, p.Target, actor)
		if err != nil || current.SID != p.Before.SID || current.DC != p.Before.DC {
			return result, ErrUncertain
		}
		to := ""
		if reflect.DeepEqual(current.Values, p.After.Values) {
			to = "reconciled_effect_observed"
		}
		if to == "" || s.Journal.Change(ctx, op, op.State, to) != nil {
			return result, ErrUncertain
		}
		result.Operation.State = to
		return result, nil
	case "apply":
		if op.State != "prepared" {
			return result, nil
		} // retry returns state, never invokes AD again
		if now.Unix() >= p.Expires || p.Policy != s.Policy {
			return result, ErrDenied
		}
		current, err := s.Directory.Read(ctx, p.Target, actor)
		if err != nil || !reflect.DeepEqual(current, p.Before) {
			return result, ErrDenied
		}
		if fresh, err := s.Directory.Authenticate(ctx, r.Username, r.Password); err != nil || fresh != actor {
			return result, ErrDenied
		}
		if time.Now().Unix() >= p.Expires || ctx.Err() != nil {
			return result, ErrDenied
		}
		if s.Journal.Change(ctx, op, "prepared", "applying") != nil {
			return result, ErrDenied
		}
		result.Operation.State = "applying"
		changes := Values{}
		for a, v := range p.After.Values {
			if !reflect.DeepEqual(v, p.Before.Values[a]) {
				changes[a] = v
			}
		}
		err = s.Directory.Modify(ctx, actor, p.Before, changes)
		state := "reconciliation_required"
		if errors.Is(err, ErrDenied) {
			state = "failed_no_effect"
		} else if err == nil {
			got, readErr := s.Directory.Read(ctx, p.Target, actor)
			if readErr == nil && got.SID == p.Before.SID && got.DC == p.Before.DC && reflect.DeepEqual(got.Values, p.After.Values) {
				state = "succeeded"
			}
		}
		// Even if the request context expired, try to preserve a bounded result.
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.Journal.Change(finish, op, "applying", state) != nil {
			return result, ErrUncertain
		}
		result.Operation.State = state
		if state == "reconciliation_required" {
			return result, ErrUncertain
		}
		return result, nil
	default:
		return result, ErrDenied
	}
}
func clone(v Values) Values {
	c := Values{}
	for a, s := range v {
		c[a] = append([]string(nil), s...)
	}
	return c
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" || r.URL.Path != "/operation" || r.URL.RawQuery != "" {
		http.Error(w, "denied", 403)
		return
	}
	var request Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "denied", 400)
		return
	}
	result, err := s.Handle(r.Context(), request)
	if err != nil {
		result.Error = "denied"
		if errors.Is(err, ErrUncertain) {
			result.Error = "reconciliation_required"
		}
		w.WriteHeader(409)
	}
	_ = json.NewEncoder(w).Encode(result)
}
