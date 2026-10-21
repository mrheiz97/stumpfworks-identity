package clientupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func acceptanceFixture(t *testing.T) (string, string, Result) {
	t.Helper()
	root := t.TempDir()
	spec := componentSpecs["sw-badge-client-status"]
	target := rootedTarget(root, spec.Target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("previous status"), spec.Mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, spec.Mode); err != nil {
		t.Fatal(err)
	}
	plan := StagePlan{ReleaseVersion: "1.4.1", Architecture: "linux-amd64", Components: []StagedComponent{{Component: "sw-badge-client-status", Target: spec.Target, Mode: uint32(spec.Mode.Perm())}}}
	rollbackDir := filepath.Join(root, "var", "backups", "stumpfworks-badge", "client-1.4.1")
	if _, err := CreateRollback(root, plan, rollbackDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	installed := []byte("accepted status")
	if err := os.WriteFile(target, installed, spec.Mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, spec.Mode); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(installed)
	result := Result{Manifest: Manifest{SchemaVersion: 1, ReleaseVersion: "1.4.1", Channel: "development", Architecture: "linux-amd64", MinimumVersion: "1.4.0", CreatedAt: time.Now(), Files: []File{{Component: "sw-badge-client-status", Size: int64(len(installed)), SHA256: hex.EncodeToString(sum[:])}}}}
	return root, rollbackDir, result
}

func TestVerifyReleaseAcceptanceValidatesInstalledAndRollback(t *testing.T) {
	root, rollbackDir, result := acceptanceFixture(t)
	plan, err := VerifyReleaseAcceptance(root, result, rollbackDir)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReleaseVersion != "1.4.1" || len(plan.Components) != 1 || plan.Components[0].Component != "sw-badge-client-status" {
		t.Fatalf("unexpected acceptance plan: %+v", plan)
	}
}

func TestVerifyReleaseAcceptanceRejectsChangedInstallation(t *testing.T) {
	root, rollbackDir, result := acceptanceFixture(t)
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if err := os.WriteFile(target, []byte("tampered status"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseAcceptance(root, result, rollbackDir); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("changed installation accepted: %v", err)
	}
}

func TestVerifyReleaseAcceptanceRejectsChangedRollback(t *testing.T) {
	root, rollbackDir, result := acceptanceFixture(t)
	backup := filepath.Join(rollbackDir, "files", "sw-badge-client-status")
	if err := os.WriteFile(backup, []byte("tampered rollback"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseAcceptance(root, result, rollbackDir); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("changed rollback accepted: %v", err)
	}
}

func TestVerifyReleaseAcceptanceRejectsWrongRollbackRelease(t *testing.T) {
	root, rollbackDir, result := acceptanceFixture(t)
	result.Manifest.ReleaseVersion = "1.4.2"
	if _, err := VerifyReleaseAcceptance(root, result, rollbackDir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong rollback release accepted: %v", err)
	}
}

func TestVerifyRollbackRejectsBroadDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX rollback permissions")
	}
	root, rollbackDir, _ := acceptanceFixture(t)
	if err := os.Chmod(rollbackDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRollback(root, rollbackDir); err == nil || !strings.Contains(err.Error(), "root-only") {
		t.Fatalf("broad rollback permissions accepted: %v", err)
	}
}
