package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
)

type updateHandlerTransport struct{ handler http.Handler }

func (t updateHandlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

type updateHealthRunner struct{}

func (updateHealthRunner) Run(context.Context, string, ...string) error { return nil }

func TestBrowserScheduledSignedUpdateThroughDeviceWorker(t *testing.T) {
	s, sessions, verified := updateServerFixture(t, adminauth.RoleClientOperator)
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	if e = os.WriteFile(payload, []byte("signed status replacement"), 0755); e != nil {
		t.Fatal(e)
	}
	artifact := filepath.Join(dir, "package.zip")
	arch := runtime.GOOS + "-" + runtime.GOARCH
	if e = clientupdate.CreateSignedPackage(artifact, private, clientupdate.PackageOptions{ReleaseVersion: "1.99.0", Channel: "stable", Architecture: arch, MinimumVersion: "1.12.2", CreatedAt: time.Now(), Components: map[string]string{"sw-badge-client-status": payload}}); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(artifact)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	result, e := clientupdate.VerifyPackageBytes(raw, public, arch, "")
	if e != nil {
		t.Fatal(e)
	}
	release := clientupdate.ApprovedRelease{ID: "approved-release-0001", SHA256: hex.EncodeToString(sum[:]), Manifest: result.Manifest, Package: raw}
	s.ConfigureUpdateCatalog(clientupdate.Catalog{release.ID: release})
	form := updateForm("end-to-end-update-001")
	if w := updateAdminRequest(s, sessions, "/client-updates", form, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	root := t.TempDir()
	target := filepath.Join(root, "usr", "local", "libexec", "sw-badge-client-status")
	if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(target, []byte("previous status"), 0755); e != nil {
		t.Fatal(e)
	}
	keyFile := filepath.Join(dir, "stable.pub")
	if e = os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(public)), 0644); e != nil {
		t.Fatal(e)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.TLS = verified; s.ClientAPIHandler().ServeHTTP(w, r) })
	o := clientupdate.WorkerOptions{Server: "https://identity.example.test:8444", ClientID: "managed-update-client", PublicKeyFile: keyFile, Directory: filepath.Join(root, "jobs"), Root: root, TransactionPath: filepath.Join(root, "transaction.json"), StatePath: filepath.Join(root, "state.json"), HTTP: &http.Client{Transport: updateHandlerTransport{handler}}, Runner: updateHealthRunner{}}
	if e = clientupdate.RunWorker(t.Context(), o); e != nil {
		t.Fatal(e)
	}
	installed, e := os.ReadFile(target)
	if e != nil || string(installed) != "signed status replacement" {
		t.Fatal("signed payload not installed", e)
	}
	jobs, e := s.store.ClientUpdateJobs(t.Context(), o.ClientID)
	if e != nil || len(jobs) != 1 || jobs[0].State != clientupdate.JobSucceeded || !jobs[0].RollbackAvailable {
		t.Fatal("result not persisted", jobs, e)
	}
	backup, e := os.ReadFile(filepath.Join(root, "var", "backups", "stumpfworks-badge", "job-"+jobs[0].ID, "files", "sw-badge-client-status"))
	if e != nil || string(backup) != "previous status" {
		t.Fatal("previous payload not preserved", e)
	}
	if e = clientupdate.RunWorker(t.Context(), o); e != nil {
		t.Fatal("completed job replay", e)
	}
}
