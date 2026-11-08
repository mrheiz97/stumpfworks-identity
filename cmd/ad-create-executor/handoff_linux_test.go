//go:build linux

package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"modernc.org/sqlite"
)

func TestRebindRollsBackLateWriteFailure(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old, next := []byte("old-binding"), []byte("next-binding")
	if _, err := db.Exec(adcreate.Schema + ";" + bindingSchema + `;
		INSERT INTO executor_binding VALUES(1,x'6f6c642d62696e64696e67');
		INSERT INTO create_ops VALUES('plan','actor','prepared',x'01',NULL);
		INSERT INTO create_names VALUES('claim','plan');
		CREATE TRIGGER fail_after_binding BEFORE INSERT ON create_audit
		WHEN NEW.event='handoff_rebound' BEGIN SELECT RAISE(ABORT,'fixture'); END;`); err != nil {
		t.Fatal(err)
	}
	if err := rebindJournal(context.Background(), db, old, next, 1); err == nil {
		t.Fatal("late audit failure was accepted")
	}
	var binding []byte
	var state string
	var audit, claims int
	if db.QueryRow(`SELECT binding FROM executor_binding`).Scan(&binding) != nil || !bytes.Equal(binding, old) ||
		db.QueryRow(`SELECT state FROM create_ops`).Scan(&state) != nil || state != "prepared" ||
		db.QueryRow(`SELECT count(*) FROM create_audit`).Scan(&audit) != nil || audit != 0 ||
		db.QueryRow(`SELECT count(*) FROM create_names`).Scan(&claims) != nil || claims != 1 {
		t.Fatal("transaction exposed a partial handoff")
	}
}

func TestRebindProcessDeath(t *testing.T) {
	const childPhase = "IDENTITY_TEST_REBIND_CRASH_PHASE"
	old, next := []byte("old-binding"), []byte("next-binding")
	if phase := os.Getenv(childPhase); phase == "before" || phase == "after" {
		db, err := sql.Open("sqlite", os.Getenv("IDENTITY_TEST_REBIND_CRASH_DB"))
		if err != nil {
			t.Fatal(err)
		}
		if phase == "before" {
			sqlite.MustRegisterScalarFunction("fixture_crash", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
				return nil, syscall.Kill(os.Getpid(), syscall.SIGKILL)
			})
			if _, err := db.Exec(`CREATE TEMP TRIGGER stop_before_commit BEFORE INSERT ON create_audit
				WHEN NEW.event='handoff_rebound' BEGIN SELECT fixture_crash(); END;`); err != nil {
				t.Fatal(err)
			}
		}
		if err := rebindJournal(context.Background(), db, old, next, 1); err != nil {
			t.Fatal(err)
		}
		if phase != "after" {
			t.Fatal("expected precommit termination")
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(adcreate.Schema+";"+bindingSchema+`;
				INSERT INTO executor_binding VALUES(1,?);
				INSERT INTO create_ops VALUES('plan','actor','prepared',x'01',NULL);
				INSERT INTO create_names VALUES('claim','plan');`, old); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestRebindProcessDeath$")
			cmd.Env = append(os.Environ(), childPhase+"="+phase, "IDENTITY_TEST_REBIND_CRASH_DB="+path)
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("expected SIGKILL: %v %s", err, output)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			wantBinding, wantState, wantAudit := old, "prepared", 0
			if phase == "after" {
				wantBinding, wantState, wantAudit = next, "cancelled", 2
			}
			var binding []byte
			var state, owner string
			var audit int
			if db.QueryRow(`SELECT binding FROM executor_binding`).Scan(&binding) != nil || !bytes.Equal(binding, wantBinding) ||
				db.QueryRow(`SELECT state FROM create_ops`).Scan(&state) != nil || state != wantState ||
				db.QueryRow(`SELECT count(*) FROM create_audit`).Scan(&audit) != nil || audit != wantAudit ||
				db.QueryRow(`SELECT id FROM create_names WHERE name='claim'`).Scan(&owner) != nil || owner != "plan" {
				t.Fatal("unexpected state after process death")
			}
		})
	}
}
