package clientupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// RemoteJob contains only bounded execution policy, never commands or URLs.
type RemoteJob struct {
	ID                string   `json:"id"`
	ClientID          string   `json:"client_id"`
	ReleaseID         string   `json:"release_id"`
	ReleaseVersion    string   `json:"release_version"`
	PackageSHA256     string   `json:"package_sha256"`
	NotBefore         int64    `json:"not_before"`
	ExpiresAt         int64    `json:"expires_at"`
	Maintenance       bool     `json:"maintenance"`
	State             JobState `json:"state"`
	RollbackAvailable bool     `json:"rollback_available"`
	CreatedAt         int64    `json:"created_at"`
	UpdatedAt         int64    `json:"updated_at"`
}
type WorkerOptions struct {
	Server, ClientID, PublicKeyFile, Directory, Root, TransactionPath, StatePath string
	HTTP                                                                         *http.Client
	Runner                                                                       CommandRunner
	Now                                                                          func() time.Time
}
type workerJournal struct {
	Job      RemoteJob `json:"job"`
	Phase    string    `json:"phase"`
	Rollback bool      `json:"rollback"`
}

// RunWorker executes at most one job. Its OS lock is released by the kernel
// on process exit, while the durable journal prevents a second execution.
func RunWorker(ctx context.Context, o WorkerOptions) error {
	u, e := url.Parse(o.Server)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || o.HTTP == nil || o.ClientID == "" || !filepath.IsAbs(o.Directory) {
		return errors.New("invalid update worker configuration")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.Root == "" {
		o.Root = "/"
	}
	if o.TransactionPath == "" {
		o.TransactionPath = DefaultTransactionPath
	}
	if o.StatePath == "" {
		o.StatePath = DefaultStatePath
	}
	if e = os.MkdirAll(o.Directory, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(o.Directory)
	if e != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		return errors.New("worker directory must be root-only")
	}
	if e = os.MkdirAll(filepath.Dir(o.TransactionPath), 0755); e != nil {
		return e
	}
	unlock, acquired, e := tryUpdateLock(o.TransactionPath + ".lock")
	if e != nil {
		return e
	}
	if !acquired {
		return nil
	}
	defer unlock()
	// No redirect can send a device credential or fetch an unapproved location.
	hc := *o.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc.Timeout = 2 * time.Minute
	o.HTTP = &hc
	if _, e = recoverPendingUpdate(ctx, o.Root, o.TransactionPath, o.StatePath, o.Runner); e != nil {
		return e
	}
	journalPath := filepath.Join(o.Directory, "job.json")
	var journal workerJournal
	raw, e := os.ReadFile(journalPath)
	if e == nil {
		if len(raw) > 8192 {
			return errors.New("worker journal too large")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&journal) != nil || d.Decode(&struct{}{}) != io.EOF || !validRemoteJob(journal.Job, o.ClientID) {
			return errors.New("invalid worker journal")
		}
		if journal.Phase == "executing" {
			// The journal is durable even when power loss erased the updater's
			// transaction marker. Restore the fixed, fully verified snapshot
			// before reporting an interrupted execution as failed.
			rollback := workerRollbackPath(o, journal.Job)
			if _, statErr := os.Lstat(rollback); statErr == nil {
				manifest, verifyErr := VerifyRollback(o.Root, rollback)
				if verifyErr != nil || manifest.ForRelease != journal.Job.ReleaseVersion {
					return errors.New("interrupted job rollback invalid")
				}
				if e = RestoreRollback(o.Root, rollback); e != nil {
					return e
				}
				plan := StagePlan{ReleaseVersion: journal.Job.ReleaseVersion}
				for _, f := range manifest.Files {
					spec := componentSpecs[f.Component]
					plan.Components = append(plan.Components, StagedComponent{Component: f.Component, Target: spec.Target, Mode: uint32(spec.Mode.Perm()), RestartLightDM: spec.RestartLightDM})
				}
				if e = PostInterruptedRecovery(ctx, plan, o.Runner)(); e != nil {
					return e
				}
				if e = WriteUpdateState(o.StatePath, UpdateState{Version: journal.Job.ReleaseVersion, Status: "failed", UpdatedAt: o.Now().UTC(), RollbackAvailable: true}); e != nil {
					return e
				}
			} else if !os.IsNotExist(statErr) {
				return statErr
			}
			journal.Phase = "failed"
			journal.Rollback = workerRollback(o, journal.Job)
			if e = writeWorkerJournal(journalPath, journal); e != nil {
				return e
			}
		}
		if journal.Phase == "succeeded" || journal.Phase == "failed" {
			return finishWorker(ctx, o, journalPath, journal)
		}
		if journal.Phase != "prepared" {
			return errors.New("invalid worker journal phase")
		}
	} else if !os.IsNotExist(e) {
		return e
	} else {
		response, e := workerRequest(ctx, o, "poll", nil)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		if response.StatusCode == 204 {
			return nil
		}
		if response.StatusCode != 200 {
			return errors.New("update polling rejected")
		}
		d := json.NewDecoder(io.LimitReader(response.Body, 8193))
		d.DisallowUnknownFields()
		if d.Decode(&journal.Job) != nil || d.Decode(&struct{}{}) != io.EOF || !validRemoteJob(journal.Job, o.ClientID) {
			return errors.New("invalid update job")
		}
		if journal.Job.State == JobDispatched {
			// Local evidence has disappeared: never treat dispatch as permission to
			// execute again. Report a conservative failed result for reconciliation.
			journal.Phase = "failed"
			journal.Rollback = workerRollback(o, journal.Job)
			if e = writeWorkerJournal(journalPath, journal); e != nil {
				return e
			}
			return finishWorker(ctx, o, journalPath, journal)
		}
		journal.Phase = "prepared"
		if e = writeWorkerJournal(journalPath, journal); e != nil {
			return e
		}
	}
	j := journal.Job
	now := o.Now()
	if now.Unix() < j.NotBefore || now.Unix() >= j.ExpiresAt {
		// A prepared job has not touched installation targets. Polling will expire
		// the server job; local preparation can safely be forgotten.
		return os.Remove(journalPath)
	}
	key, e := LoadPublicKey(o.PublicKeyFile)
	if e != nil {
		return e
	}
	dir := filepath.Join(o.Directory, j.ID)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	packagePath := filepath.Join(dir, "package.zip")
	// Re-download is safe before the executing journal is committed. Stage
	// directories are create-only, so incomplete preparation uses a new name.
	response, e := workerRequest(ctx, o, j.ID+"/package", nil)
	if e != nil {
		return e
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		if response.StatusCode == 409 || response.StatusCode == 404 {
			return os.Remove(journalPath)
		}
		return errors.New("update package rejected")
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, maxPackageSize+(1<<20)+1))
	response.Body.Close()
	if e != nil || len(data) > maxPackageSize+(1<<20) {
		return errors.New("update download failed")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != j.PackageSHA256 {
		return errors.New("update package digest mismatch")
	}
	if e = writeWorkerFile(packagePath, data); e != nil {
		return e
	}
	currentVersion := version.Version
	lastState, stateErr := ReadUpdateState(o.StatePath)
	if stateErr != nil {
		return stateErr
	}
	if lastState != nil && lastState.Status == "success" && compareVersions(lastState.Version, currentVersion) > 0 {
		currentVersion = lastState.Version
	}
	verified, e := VerifyPackage(packagePath, key, runtime.GOOS+"-"+runtime.GOARCH, currentVersion)
	if e != nil || verified.Manifest.Channel != "stable" || verified.Manifest.ReleaseVersion != j.ReleaseVersion {
		return errors.New("update release verification failed")
	}
	stage, e := os.MkdirTemp(dir, "stage-")
	if e != nil {
		return e
	}
	if e = os.Remove(stage); e != nil {
		return e
	}
	plan, e := VerifyAndStage(packagePath, key, runtime.GOOS+"-"+runtime.GOARCH, currentVersion, stage)
	if e != nil {
		return e
	}
	if RequiresLightDMMaintenance(plan) && !j.Maintenance {
		return errors.New("update requires maintenance authorization")
	}
	if o.Now().Unix() >= j.ExpiresAt {
		return errors.New("execution window ended during preparation")
	}
	response, e = workerRequest(ctx, o, j.ID+"/start", nil)
	if e != nil {
		return e
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		if response.StatusCode == 409 || response.StatusCode == 404 {
			return os.Remove(journalPath)
		}
		return errors.New("update execution rejected")
	}
	// Persist before the first possible target change. A lost start response
	// retries only the grant; an executing journal never repeats installation.
	journal.Phase = "executing"
	if e = writeWorkerJournal(journalPath, journal); e != nil {
		return e
	}
	rollback := workerRollbackPath(o, j)
	health, recovery := UpdateHealthCallbacks(ctx, plan, o.Runner, o.StatePath, o.Now().UTC())
	e = installStagedWithTransaction(o.Root, stage, rollback, o.TransactionPath, o.Now().UTC(), j.Maintenance, health, recovery)
	journal.Phase = "succeeded"
	if e != nil {
		journal.Phase = "failed"
	}
	// If rollback recovery remains incomplete, retain executing evidence and
	// retry recovery before any result is acknowledged.
	if pending, readErr := ReadUpdateTransaction(o.TransactionPath); readErr != nil || pending != nil {
		return errors.New("update recovery pending")
	}
	journal.Rollback = workerRollback(o, j)
	if err := writeWorkerJournal(journalPath, journal); err != nil {
		return err
	}
	return finishWorker(ctx, o, journalPath, journal)
}
func validRemoteJob(j RemoteJob, client string) bool {
	id := regexp.MustCompile(`^[a-zA-Z0-9_-]{16,64}$`)
	digest, e := hex.DecodeString(j.PackageSHA256)
	return j.ClientID == client && id.MatchString(j.ID) && id.MatchString(j.ReleaseID) && validVersion(j.ReleaseVersion) && e == nil && len(digest) == 32 && j.ExpiresAt > j.NotBefore && j.ExpiresAt-j.NotBefore <= 86400 && (j.State == JobScheduled || j.State == JobDispatched)
}
func workerRequest(ctx context.Context, o WorkerOptions, suffix string, payload any) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		raw, e := json.Marshal(payload)
		if e != nil {
			return nil, e
		}
		body = bytes.NewReader(raw)
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.Server, "/")+"/api/v1/client/updates/"+suffix, body)
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	return o.HTTP.Do(r)
}
func workerRollbackPath(o WorkerOptions, j RemoteJob) string {
	return rootedTarget(o.Root, "/var/backups/stumpfworks-badge/job-"+j.ID)
}
func workerRollback(o WorkerOptions, j RemoteJob) bool {
	m, e := VerifyRollback(o.Root, workerRollbackPath(o, j))
	return e == nil && m.ForRelease == j.ReleaseVersion
}
func finishWorker(ctx context.Context, o WorkerOptions, path string, j workerJournal) error {
	response, e := workerRequest(ctx, o, j.Job.ID+"/result", map[string]any{"state": j.Phase, "rollback_available": j.Rollback})
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 204 {
		return errors.New("update result not acknowledged")
	}
	return os.Remove(path)
}
func writeWorkerJournal(path string, j workerJournal) error {
	raw, e := json.Marshal(j)
	if e != nil {
		return e
	}
	return writeWorkerFile(path, raw)
}
func writeWorkerFile(path string, raw []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".job-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	if runtime.GOOS != "windows" {
		d, e := os.Open(filepath.Dir(path))
		if e != nil {
			return e
		}
		defer d.Close()
		return d.Sync()
	}
	return nil
}
