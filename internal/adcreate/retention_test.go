package adcreate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMaintenancePreservesReplayFences(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"succeeded", "uncertain", "applying"} {
		t.Run(state, func(t *testing.T) {
			s, d := setup(t)
			op := prepare(t, s)
			if state != "succeeded" {
				d.after = func() error { return ErrUncertain }
			}
			if _, err := confirm(s, op); (err == nil) != (state == "succeeded") {
				t.Fatal(err)
			}
			if state == "applying" {
				// Model a process that stopped after committing the dispatch claim.
				if _, err := s.db.Exec(`UPDATE create_ops SET state='applying' WHERE id=?`, op.Plan.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Maintain(ctx, time.Now().Add(91*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
			status, err := s.Action(ctx, "operator", "secret", op.Plan.ID, "status", "")
			if err != nil || status.State != state || status.Plan.ID != op.Plan.ID {
				t.Fatalf("state lost: %+v, %v", status, err)
			}
			if state == "succeeded" {
				if status.Plan.Input != (Input{}) || status.Result != (Result{}) {
					t.Fatal("terminal personal data retained")
				}
				var dispatches int
				if s.db.QueryRow(`SELECT COUNT(*) FROM create_dispatch`).Scan(&dispatches) != nil || dispatches != 0 {
					t.Fatal("terminal dispatch retained")
				}
			} else if _, err := s.binding(ctx, status.Plan); err != nil {
				t.Fatal("unresolved dispatch erased", err)
			}
			events, err := s.History(ctx, "operator", "secret", op.Plan.ID)
			if err != nil || len(events) == 0 || (state == "succeeded" && (len(events) != 1 || events[0].Event != "payload_erased")) {
				t.Fatal("unexpected retained audit", events, err)
			}
			if _, err := s.Prepare(ctx, "operator", "secret", op.Plan.Input); err == nil {
				t.Fatal("reserved name released")
			}
			if _, err := confirm(s, op); err == nil || d.sends != 1 {
				t.Fatal("operation replayed")
			}
		})
	}
}

func TestMaintenanceExpiresPlansAtomically(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()
	op := prepare(t, s)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_expiration BEFORE INSERT ON create_audit WHEN NEW.event='expired' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(op.Plan.Expires, 0)
	if err := s.Maintain(ctx, now); err == nil {
		t.Fatal("audit failure ignored")
	}
	var state string
	var claims int
	if s.db.QueryRow(`SELECT state FROM create_ops WHERE id=?`, op.Plan.ID).Scan(&state) != nil || state != "prepared" ||
		s.db.QueryRow(`SELECT COUNT(*) FROM create_names WHERE id=?`, op.Plan.ID).Scan(&claims) != nil || claims != 2 {
		t.Fatal("partial expiration")
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_expiration`); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(ctx, now); err != nil {
		t.Fatal(err)
	}
	if fresh, err := s.Prepare(ctx, "operator", "secret", op.Plan.Input); err != nil || fresh.Plan.ID == op.Plan.ID {
		t.Fatal("expired name not available for a new plan", err)
	}
	s.RecoveryOnly = true
	if err := s.Maintain(ctx, now); !errors.Is(err, ErrDenied) {
		t.Fatal("maintenance modified a recovery snapshot", err)
	}
}
