package clientupdate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoverPendingUpdateRestoresInterruptedInstallation(t *testing.T) {
	root := t.TempDir()
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old status"), 0755); err != nil {
		t.Fatal(err)
	}
	rollbackDir := filepath.Join(root, "var", "backups", "stumpfworks-badge", "rollback")
	started := time.Unix(100, 0).UTC()
	plan := StagePlan{ReleaseVersion: "1.4.1", Components: []StagedComponent{{Component: "sw-badge-client-status", Target: componentSpecs["sw-badge-client-status"].Target, Mode: 0755}}}
	if _, err := CreateRollback(root, plan, rollbackDir, started); err != nil {
		t.Fatal(err)
	}
	transactionPath := filepath.Join(t.TempDir(), "update-transaction.json")
	if err := WriteUpdateTransaction(transactionPath, UpdateTransaction{SchemaVersion: 1, ReleaseVersion: plan.ReleaseVersion, RollbackDir: rollbackDir, StartedAt: started}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("partially installed status"), 0755); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "update-state.json")
	runner := &fakeRunner{}
	recovered, err := RecoverPendingUpdate(context.Background(), root, transactionPath, statePath, runner)
	if err != nil || !recovered {
		t.Fatalf("pending recovery failed: recovered=%t err=%v", recovered, err)
	}
	restored, err := os.ReadFile(target)
	if err != nil || string(restored) != "old status" {
		t.Fatalf("interrupted target was not restored: %q %v", restored, err)
	}
	if _, err = os.Stat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("completed transaction marker remained: %v", err)
	}
	state, err := ReadUpdateState(statePath)
	if err != nil || state == nil || state.Status != "failed" || state.Version != plan.ReleaseVersion || !state.RollbackAvailable {
		t.Fatalf("unexpected recovered update state: %+v %v", state, err)
	}
	wantCalls := "systemctl is-active swbadge-client-status.timer|systemctl is-active lightdm.service"
	if strings.Join(runner.calls, "|") != wantCalls {
		t.Fatalf("unexpected interrupted-recovery calls: %v", runner.calls)
	}
}

func TestRecoverPendingUpdateIsNoOpWithoutMarker(t *testing.T) {
	recovered, err := RecoverPendingUpdate(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "missing.json"), filepath.Join(t.TempDir(), "state.json"), &fakeRunner{})
	if err != nil || recovered {
		t.Fatalf("unexpected no-marker result: recovered=%t err=%v", recovered, err)
	}
}

func TestRecoverPendingUpdateRejectsMismatchedRollback(t *testing.T) {
	root := t.TempDir()
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("original"), 0755); err != nil {
		t.Fatal(err)
	}
	rollbackDir := filepath.Join(root, "var", "backups", "stumpfworks-badge", "rollback")
	plan := StagePlan{ReleaseVersion: "1.4.1", Components: []StagedComponent{{Component: "sw-badge-client-status", Target: componentSpecs["sw-badge-client-status"].Target, Mode: 0755}}}
	if _, err := CreateRollback(root, plan, rollbackDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	transactionPath := filepath.Join(t.TempDir(), "transaction.json")
	if err := WriteUpdateTransaction(transactionPath, UpdateTransaction{SchemaVersion: 1, ReleaseVersion: "1.4.2", RollbackDir: rollbackDir, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	recovered, err := RecoverPendingUpdate(context.Background(), root, transactionPath, filepath.Join(t.TempDir(), "state.json"), &fakeRunner{})
	if err == nil || !recovered || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched rollback was accepted: recovered=%t err=%v", recovered, err)
	}
	current, _ := os.ReadFile(target)
	if string(current) != "original" {
		t.Fatalf("target changed after rejected recovery: %q", current)
	}
}

func TestRecoverPendingUpdateRejectsRollbackOutsideManagedDirectory(t *testing.T) {
	root := t.TempDir()
	transactionPath := filepath.Join(t.TempDir(), "transaction.json")
	if err := WriteUpdateTransaction(transactionPath, UpdateTransaction{SchemaVersion: 1, ReleaseVersion: "1.4.1", RollbackDir: filepath.Join(t.TempDir(), "rollback"), StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	recovered, err := RecoverPendingUpdate(context.Background(), root, transactionPath, filepath.Join(t.TempDir(), "state.json"), &fakeRunner{})
	if err == nil || !recovered || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside rollback was accepted: recovered=%t err=%v", recovered, err)
	}
}
