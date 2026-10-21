package clientupdate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installFixture(t *testing.T) (string, string) {
	t.Helper()
	payload := []byte("new status binary")
	packagePath, key := testPackage(t, payload, nil, "")
	stageDir := filepath.Join(t.TempDir(), "stage")
	if _, err := VerifyAndStage(packagePath, key, "linux-amd64", "1.2.0-dev", stageDir); err != nil {
		t.Fatal(err)
	}
	return t.TempDir(), stageDir
}

func TestInstallStagedCreatesRollbackAndInstalls(t *testing.T) {
	root, stageDir := installFixture(t)
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old status binary"), 0755); err != nil {
		t.Fatal(err)
	}
	rollbackDir := filepath.Join(t.TempDir(), "rollback")
	if err := InstallStaged(root, stageDir, rollbackDir, time.Now(), false, func() error { return nil }, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(target)
	if err != nil || string(installed) != "new status binary" {
		t.Fatalf("unexpected installed file: %q, %v", installed, err)
	}
	backup, err := os.ReadFile(filepath.Join(rollbackDir, "files", "sw-badge-client-status"))
	if err != nil || string(backup) != "old status binary" {
		t.Fatalf("unexpected rollback file: %q, %v", backup, err)
	}
}

func TestInstallFailureAutomaticallyRestoresAllTargets(t *testing.T) {
	root, stageDir := installFixture(t)
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old status binary"), 0755); err != nil {
		t.Fatal(err)
	}
	rollbackDir := filepath.Join(t.TempDir(), "rollback")
	recovered := false
	err := installStaged(root, stageDir, rollbackDir, "", time.Now(), false, func(_ int, _ StagedComponent) error { return errors.New("injected installation failure") }, func() error { return nil }, func() error { recovered = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("unexpected error: %v", err)
	}
	restored, readErr := os.ReadFile(target)
	if readErr != nil || string(restored) != "old status binary" {
		t.Fatalf("automatic rollback failed: %q, %v", restored, readErr)
	}
	if !recovered {
		t.Fatal("post-rollback recovery was not invoked")
	}
}

func TestInstallRejectsTamperedStageBeforeRollbackOrTargetChange(t *testing.T) {
	root, stageDir := installFixture(t)
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old status binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "payload", "sw-badge-client-status"), []byte("tampered"), 0755); err != nil {
		t.Fatal(err)
	}
	rollbackDir := filepath.Join(t.TempDir(), "rollback")
	if err := InstallStaged(root, stageDir, rollbackDir, time.Now(), false, func() error { return nil }, func() error { return nil }); err == nil || !strings.Contains(err.Error(), "validate") {
		t.Fatalf("unexpected error: %v", err)
	}
	current, _ := os.ReadFile(target)
	if string(current) != "old status binary" {
		t.Fatal("target changed after rejected stage")
	}
	if _, err := os.Stat(rollbackDir); !os.IsNotExist(err) {
		t.Fatal("rollback created for invalid stage")
	}
}

func TestFailedPostInstallHealthCheckRestoresInstalledFile(t *testing.T) {
	root, stageDir := installFixture(t)
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old status binary"), 0755); err != nil {
		t.Fatal(err)
	}
	rollbackDir := filepath.Join(t.TempDir(), "rollback")
	err := InstallStaged(root, stageDir, rollbackDir, time.Now(), false, func() error {
		installed, readErr := os.ReadFile(target)
		if readErr != nil || string(installed) != "new status binary" {
			return errors.New("new binary not visible to health check")
		}
		return errors.New("injected unhealthy state")
	}, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("unexpected health-check error: %v", err)
	}
	restored, readErr := os.ReadFile(target)
	if readErr != nil || string(restored) != "old status binary" {
		t.Fatalf("health rollback failed: %q, %v", restored, readErr)
	}
}

func TestCrashSafeInstallPersistsMarkerBeforeApplyAndClearsItAfterHealth(t *testing.T) {
	root, stageDir := installFixture(t)
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old status binary"), 0755); err != nil {
		t.Fatal(err)
	}
	rollbackDir := filepath.Join(t.TempDir(), "rollback")
	transactionPath := filepath.Join(t.TempDir(), "update-transaction.json")
	markerSeen := false
	err := installStaged(root, stageDir, rollbackDir, transactionPath, time.Now(), false, func(_ int, _ StagedComponent) error {
		transaction, readErr := ReadUpdateTransaction(transactionPath)
		markerSeen = readErr == nil && transaction != nil && transaction.RollbackDir == rollbackDir
		return readErr
	}, func() error { return nil }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !markerSeen {
		t.Fatal("transaction marker was not durable before the first file replacement")
	}
	if _, err = os.Stat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("successful transaction marker remained: %v", err)
	}
}
