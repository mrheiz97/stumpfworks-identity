package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
)

type releaseRehearsalHealth struct {
	t            *testing.T
	target       string
	failOnce     bool
	statusStarts int
}

func (r *releaseRehearsalHealth) Run(_ context.Context, name string, args ...string) error {
	if name != "systemctl" {
		r.t.Fatalf("unexpected command: %s", name)
	}
	switch strings.Join(args, " ") {
	case "start swbadge-client-status.service", "is-active swbadge-client-status.timer", "is-active lightdm.service":
	default:
		r.t.Fatalf("unexpected service action: %v", args)
	}
	if strings.Join(args, " ") == "start swbadge-client-status.service" {
		r.statusStarts++
		out, err := exec.Command(r.target, "--version").Output()
		if err != nil {
			r.t.Fatal("real status executable failed", err)
		}
		if r.statusStarts == 1 && strings.TrimSpace(string(out)) != "sw-badge-client-status 1.13.1" {
			r.t.Fatal("health did not observe real new binary")
		}
		if r.failOnce {
			r.failOnce = false
			return errors.New("isolated health failure")
		}
	}
	return nil
}

// Opt-in rehearsal of the actual Stable-signed Linux package. The same test can
// be compiled against immutable v1.13.0 to exercise the installed worker code.
// HTTP/TLS identities and stores are synthetic; systemctl is never executed.
func TestPreparedWYSE01ReleaseThroughScheduledWorker(t *testing.T) {
	dir := os.Getenv("IDENTITY_TEST_WYSE01_V1131")
	if dir == "" {
		t.Skip("actual release preparation kit not supplied")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("actual Linux executables require isolated Linux-amd64")
	}
	if version.Version != "1.13.0" {
		t.Skip("compile this opt-in compatibility rehearsal against immutable v1.13.0")
	}
	keyFile := filepath.Join(dir, "stable-update-ed25519.pub")
	key, err := clientupdate.LoadPublicKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(key)
	if hex.EncodeToString(fp[:]) != "d94bd2573b017898d771913f358bff5386af5b300392bcc75ec02d8e42fec069" {
		t.Fatal("wrong stable key")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "wyse01-status-1_13_1.zip"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := clientupdate.VerifyPackageBytes(raw, key, "linux-amd64", "1.13.0")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Manifest.ReleaseVersion != "1.13.1" || verified.Manifest.Channel != "stable" || verified.Manifest.MinimumVersion != "1.13.0" || len(verified.Files) != 1 || verified.Files[0] != "sw-badge-client-status" {
		t.Fatal("unexpected signed package scope")
	}
	catalog, err := clientupdate.LoadCatalog(filepath.Join(dir, "catalog"), keyFile)
	if err != nil || len(catalog) != 1 {
		t.Fatal("actual catalog proposal rejected", err)
	}
	approved := catalog["wyse01-status-1_13_1"]
	if !bytes.Equal(approved.Package, raw) || approved.RequiresMaintenance {
		t.Fatal("catalog bytes/scope do not match prepared package")
	}
	for _, tc := range []struct{ arch, current string }{{"linux-amd64", "1.13.1"}, {"linux-amd64", "1.14.0"}, {"linux-amd64", "1.12.2"}, {"linux-arm64", "1.13.0"}} {
		if _, e := clientupdate.VerifyPackageBytes(raw, key, tc.arch, tc.current); e == nil {
			t.Fatal("invalid version/architecture accepted", tc)
		}
	}
	if _, e := clientupdate.VerifyPackageBytes(raw, make([]byte, 32), "linux-amd64", "1.13.0"); e == nil {
		t.Fatal("wrong key accepted")
	}
	old, err := os.ReadFile(filepath.Join(dir, "baseline-public-binaries", "sw-badge-client-status"))
	if err != nil {
		t.Fatal(err)
	}
	oldHash := sha256.Sum256(old)
	if hex.EncodeToString(oldHash[:]) != "324dc17c81e1d08b6e977ab6fd53f780b78637fdc81bc02b7724b253e27b14aa" {
		t.Fatal("wrong baseline binary")
	}
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "health-rollback"}[failure], func(t *testing.T) {
			s, sessions, tlsState := updateServerFixture(t, adminauth.RoleClientOperator)
			sum := sha256.Sum256(raw)
			release := clientupdate.ApprovedRelease{ID: "wyse01-status-1_13_1", SHA256: hex.EncodeToString(sum[:]), Manifest: verified.Manifest, Package: raw}
			s.ConfigureUpdateCatalog(clientupdate.Catalog{release.ID: release})
			form := updateForm("rehearsal-cancelled-0001")
			form.Set("release_id", release.ID)
			if w := updateAdminRequest(s, sessions, "/client-updates", form, true); w.Code != 303 {
				t.Fatal("schedule", w.Code)
			}
			if w := updateAdminRequest(s, sessions, "/client-updates/rehearsal-cancelled-0001/cancel", nil, true); w.Code != 303 {
				t.Fatal("cancel", w.Code)
			}
			form = updateForm("rehearsal-executed-0001")
			form.Set("release_id", release.ID)
			if w := updateAdminRequest(s, sessions, "/client-updates", form, true); w.Code != 303 {
				t.Fatal("schedule", w.Code)
			}
			root := t.TempDir()
			target := filepath.Join(root, "usr/local/libexec/sw-badge-client-status")
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, old, 0755); err != nil {
				t.Fatal(err)
			}
			runner := &releaseRehearsalHealth{t: t, target: target, failOnce: failure}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.TLS = tlsState; s.ClientAPIHandler().ServeHTTP(w, r) })
			o := clientupdate.WorkerOptions{Server: "https://identity.example.test:8444", ClientID: "managed-update-client", PublicKeyFile: keyFile, Directory: filepath.Join(root, "jobs"), Root: root, TransactionPath: filepath.Join(root, "transaction.json"), StatePath: filepath.Join(root, "state.json"), HTTP: &http.Client{Transport: updateHandlerTransport{handler}}, Runner: runner}
			if err := clientupdate.RunWorker(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			jobs, err := s.store.ClientUpdateJobs(t.Context(), o.ClientID)
			if err != nil {
				t.Fatal(err)
			}
			want := clientupdate.JobSucceeded
			if failure {
				want = clientupdate.JobFailed
			}
			found, cancelled := false, false
			for _, j := range jobs {
				if j.ID == "rehearsal-cancelled-0001" {
					cancelled = j.State == clientupdate.JobCancelled
				}
				if j.ID == "rehearsal-executed-0001" {
					found = j.State == want && j.RollbackAvailable
				}
			}
			if !found || !cancelled {
				t.Fatal("job lifecycle mismatch", jobs)
			}
			wantStarts := 1
			if failure {
				wantStarts = 2
			}
			if runner.statusStarts != wantStarts {
				t.Fatal("health/recovery invocation mismatch", runner.statusStarts)
			}
			rollback := filepath.Join(root, "var/backups/stumpfworks-badge/job-rehearsal-executed-0001")
			if _, err := clientupdate.VerifyRollback(root, rollback); err != nil {
				t.Fatal(err)
			}
			if !failure {
				if err := clientupdate.RestoreRollback(root, rollback); err != nil {
					t.Fatal(err)
				}
			}
			restored, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(restored, old) {
				t.Fatal("rollback not byte-exact", err)
			}
			before := runner.statusStarts
			if err := clientupdate.RunWorker(t.Context(), o); err != nil {
				t.Fatal("completed-job replay", err)
			}
			if runner.statusStarts != before {
				t.Fatal("completed job installed again")
			}
		})
	}
}
