package clientupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type workerTransport func(*http.Request) (*http.Response, error)

func (f workerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func workerFixture(t *testing.T) (WorkerOptions, RemoteJob, []byte, string) {
	t.Helper()
	p, key := testPackage(t, []byte("new managed status"), func(m *Manifest, raw *[]byte) {
		m.Channel = "stable"
		m.ReleaseVersion = "1.99.0"
		m.Architecture = runtime.GOOS + "-" + runtime.GOARCH
		*raw, _ = json.Marshal(m)
	}, "")
	data, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	keyFile := filepath.Join(root, "key.pub")
	if e = os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)), 0600); e != nil {
		t.Fatal(e)
	}
	target := rootedTarget(root, componentSpecs["sw-badge-client-status"].Target)
	if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(target, []byte("old status"), 0755); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Truncate(time.Second)
	sum := sha256.Sum256(data)
	j := RemoteJob{ID: "worker-update-job-0001", ClientID: "worker-client", ReleaseID: "approved-release-0001", ReleaseVersion: "1.99.0", PackageSHA256: hex.EncodeToString(sum[:]), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), State: JobScheduled}
	o := WorkerOptions{Server: "https://updates.example.test", ClientID: j.ClientID, PublicKeyFile: keyFile, Directory: filepath.Join(root, "jobs"), Root: root, TransactionPath: filepath.Join(root, "transaction.json"), StatePath: filepath.Join(root, "state.json"), Runner: &fakeRunner{}, Now: func() time.Time { return now }}
	return o, j, data, target
}
func TestWorkerLostStartAndResultResponsesDoNotRepeatInstallation(t *testing.T) {
	o, j, data, target := workerFixture(t)
	starts, results := 0, 0
	var outcome string
	o.HTTP = &http.Client{Transport: workerTransport(func(r *http.Request) (*http.Response, error) {
		code := 204
		body := []byte{}
		switch {
		case strings.HasSuffix(r.URL.Path, "/poll"):
			body, _ = json.Marshal(j)
			code = 200
		case strings.HasSuffix(r.URL.Path, "/package"):
			body = data
			code = 200
		case strings.HasSuffix(r.URL.Path, "/start"):
			starts++
			if starts == 1 {
				return nil, errors.New("lost start response")
			}
		case strings.HasSuffix(r.URL.Path, "/result"):
			results++
			var v struct {
				State string `json:"state"`
			}
			json.NewDecoder(r.Body).Decode(&v)
			outcome = v.State
			if results == 1 {
				return nil, errors.New("lost result response")
			}
		default:
			t.Fatal("unexpected worker request", r.URL.Path)
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	if e := RunWorker(t.Context(), o); e == nil {
		t.Fatal("lost start response ignored")
	}
	if b, _ := os.ReadFile(target); string(b) != "old status" {
		t.Fatal("installed before start acknowledgment")
	}
	if e := RunWorker(t.Context(), o); e == nil {
		t.Fatal("lost result response ignored")
	} else {
		t.Log("second attempt:", e)
	}
	if b, _ := os.ReadFile(target); string(b) != "new managed status" {
		t.Fatal("installation failed")
	}
	// Changing the target proves retry sends only the saved result.
	if e := os.WriteFile(target, []byte("after completed update"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := RunWorker(t.Context(), o); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(target); string(b) != "after completed update" {
		t.Fatal("installation repeated")
	}
	if starts != 2 || results != 2 || outcome != "succeeded" {
		t.Fatal(starts, results, outcome)
	}
}
func TestWorkerCrashJournalNeverReexecutes(t *testing.T) {
	o, j, _, target := workerFixture(t)
	if e := os.MkdirAll(o.Directory, 0700); e != nil {
		t.Fatal(e)
	}
	if e := writeWorkerJournal(filepath.Join(o.Directory, "job.json"), workerJournal{Job: j, Phase: "executing"}); e != nil {
		t.Fatal(e)
	}
	calls := 0
	o.HTTP = &http.Client{Transport: workerTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.HasSuffix(r.URL.Path, "/result") {
			t.Fatal("crash caused another execution", r.URL.Path)
		}
		var result struct {
			State string `json:"state"`
		}
		json.NewDecoder(r.Body).Decode(&result)
		if result.State != "failed" {
			t.Fatal("uncertain execution was successful")
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	if e := RunWorker(t.Context(), o); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(target); string(b) != "old status" || calls != 1 {
		t.Fatal("target changed after process interruption")
	}
}

func TestWorkerJournalRecoversWithoutTransactionMarker(t *testing.T) {
	o, j, _, target := workerFixture(t)
	if e := os.MkdirAll(o.Directory, 0700); e != nil {
		t.Fatal(e)
	}
	plan := StagePlan{ReleaseVersion: j.ReleaseVersion, Components: []StagedComponent{{Component: "sw-badge-client-status", Target: componentSpecs["sw-badge-client-status"].Target, Mode: 0755}}}
	if _, e := CreateRollback(o.Root, plan, workerRollbackPath(o, j), o.Now()); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(target, []byte("partially installed"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := writeWorkerJournal(filepath.Join(o.Directory, "job.json"), workerJournal{Job: j, Phase: "executing"}); e != nil {
		t.Fatal(e)
	}
	o.HTTP = &http.Client{Transport: workerTransport(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/result") {
			t.Fatal("interrupted job reexecuted")
		}
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), `"state":"failed"`) || !strings.Contains(string(b), `"rollback_available":true`) {
			t.Fatal(string(b))
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	if e := RunWorker(t.Context(), o); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(target); string(b) != "old status" {
		t.Fatal("rollback not restored without marker")
	}
}
func TestWorkerRejectsTamperedArtifactAndForeignJob(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(string(rune('a'+map[bool]int{false: 0, true: 1}[foreign])), func(t *testing.T) {
			o, j, data, target := workerFixture(t)
			if foreign {
				j.ClientID = "foreign"
			} else {
				data = append(data, 'x')
			}
			o.HTTP = &http.Client{Transport: workerTransport(func(r *http.Request) (*http.Response, error) {
				body, _ := json.Marshal(j)
				if strings.HasSuffix(r.URL.Path, "/package") {
					body = data
				} else if !strings.HasSuffix(r.URL.Path, "/poll") {
					t.Fatal("unverified job reached execution")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			if e := RunWorker(t.Context(), o); e == nil {
				t.Fatal("invalid job accepted")
			}
			if b, _ := os.ReadFile(target); string(b) != "old status" {
				t.Fatal("target changed")
			}
		})
	}
}
func TestUpdateLockPreventsRecoveryDuringLiveInstall(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "transaction.json")
	unlock, ok, e := tryUpdateLock(marker + ".lock")
	if e != nil || !ok {
		t.Fatal(e)
	}
	defer unlock()
	if e = os.WriteFile(marker, []byte("not a transaction"), 0600); e != nil {
		t.Fatal(e)
	}
	if recovered, e := RecoverPendingUpdate(context.Background(), root, marker, filepath.Join(root, "state"), &fakeRunner{}); e != nil || recovered {
		t.Fatal("active install was recovered", e)
	}
}
