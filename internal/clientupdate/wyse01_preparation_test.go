package clientupdate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerEmptyPollDoesNotInstallOrCreateJobEvidence(t *testing.T) {
	o, _, _, target := workerFixture(t)
	polls := 0
	o.HTTP = &http.Client{Transport: workerTransport(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/poll") {
			t.Fatalf("empty poll requested unexpected action: %s", r.URL.Path)
		}
		polls++
		return &http.Response{StatusCode: 204, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})}
	for range 3 {
		if err := RunWorker(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	if polls != 3 || len(o.Runner.(*fakeRunner).calls) != 0 {
		t.Fatal("empty polling performed service actions")
	}
	for _, path := range []string{filepath.Join(o.Directory, "job.json"), o.TransactionPath, o.StatePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("unexpected job/update evidence at %s: %v", path, err)
		}
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "old status" {
		t.Fatal("empty poll changed target", err)
	}
}

// A current-version job must fail before the server grants execution, even
// when its package is correctly signed and its approval digest is correct.
func TestWorkerAlreadyInstalledReleaseNeverRequestsStart(t *testing.T) {
	o, j, data, target := workerFixture(t)
	if err := WriteUpdateState(o.StatePath, UpdateState{Version: j.ReleaseVersion, Status: "success", UpdatedAt: o.Now()}); err != nil {
		t.Fatal(err)
	}
	o.HTTP = &http.Client{Transport: workerTransport(func(r *http.Request) (*http.Response, error) {
		var body []byte
		switch {
		case strings.HasSuffix(r.URL.Path, "/poll"):
			body, _ = json.Marshal(j)
		case strings.HasSuffix(r.URL.Path, "/package"):
			body = data
		default:
			t.Fatalf("already installed release requested execution/result: %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	if RunWorker(t.Context(), o) == nil {
		t.Fatal("already installed release accepted")
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "old status" {
		t.Fatal("installation target changed", err)
	}
}

// Optional local release evidence: CI runs synthetic security contracts; this
// test additionally loads the actual previously signed, immutable release ZIP.
func TestWYSE01PreparedStableCatalog(t *testing.T) {
	dir := os.Getenv("IDENTITY_TEST_WYSE01_PREPARATION")
	if dir == "" {
		t.Skip("local release preparation kit not supplied")
	}
	keyPath := filepath.Join(dir, "server", "update-stable.pub")
	key, err := LoadPublicKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(key)
	if hex.EncodeToString(sum[:]) != "d94bd2573b017898d771913f358bff5386af5b300392bcc75ec02d8e42fec069" {
		t.Fatal("unexpected stable key")
	}
	empty, err := LoadCatalog(filepath.Join(dir, "server", "releases"), keyPath)
	if err != nil || len(empty) != 0 {
		t.Fatal("activation catalog must be empty", err)
	}
	catalog, err := LoadCatalog(filepath.Join(dir, "verification-catalog"), keyPath)
	if err != nil || len(catalog) != 1 {
		t.Fatal("actual signed catalog verification failed", err)
	}
	r := catalog["wyse01-v1130-status-updater"]
	if r.Manifest.ReleaseVersion != "1.13.0" || r.RequiresMaintenance || len(r.Manifest.Files) != 2 {
		t.Fatal("unexpected release scope")
	}
	if _, err := VerifyPackageBytes(r.Package, key, "linux-amd64", "1.13.0"); err == nil {
		t.Fatal("equal-version package accepted")
	}
	if _, err := VerifyPackageBytes(r.Package, key, "linux-amd64", "1.14.0"); err == nil {
		t.Fatal("downgrade accepted")
	}
	if _, err := VerifyPackageBytes(r.Package, key, "linux-arm64", ""); err == nil {
		t.Fatal("wrong architecture accepted")
	}
	worker, err := os.ReadFile(filepath.Join(dir, "client", "sw-badge-client-update-worker"))
	if err != nil {
		t.Fatal(err)
	}
	workerSum := sha256.Sum256(worker)
	if hex.EncodeToString(workerSum[:]) != "e0ca7b649f8c702c051eac0a25c1b8479d64e75f729f997c7305c429a5698492" {
		t.Fatal("worker release hash mismatch")
	}
}
