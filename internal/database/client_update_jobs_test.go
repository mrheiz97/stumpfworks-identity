package database

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
)

type updateJobStore interface {
	CreateClient(context.Context, string, string) (Client, error)
	CreateClientUpdateJob(context.Context, ClientUpdateJob, string, string, time.Time) error
	ChangeClientUpdateJob(context.Context, string, string, clientupdate.JobState, bool, string, string, time.Time) error
	ClientUpdateJobs(context.Context, string) ([]ClientUpdateJob, error)
}

func testUpdateJobContract(t *testing.T, s updateJobStore, setMode func(string), auditFailure func(bool)) {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	client := "update-contract-client"
	if _, e := s.CreateClient(ctx, client, "synthetic-hash"); e != nil {
		t.Fatal(e)
	}
	j := ClientUpdateJob{ID: "update-contract-0001", ClientID: client, ReleaseID: "approved-release-0001", ReleaseVersion: "1.13.0", PackageSHA256: strings.Repeat("a", 64), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	if e := s.CreateClientUpdateJob(ctx, j, "operator", "", now); e == nil {
		t.Fatal("token-only client accepted")
	}
	setMode(client)
	auditFailure(true)
	if e := s.CreateClientUpdateJob(ctx, j, "operator", "", now); e == nil {
		t.Fatal("audit failure committed job")
	}
	auditFailure(false)
	if jobs, e := s.ClientUpdateJobs(ctx, client); e != nil || len(jobs) != 0 {
		t.Fatal("partial job persisted", jobs, e)
	}
	for i := 0; i < 2; i++ {
		if e := s.CreateClientUpdateJob(ctx, j, "operator", "", now); e != nil {
			t.Fatal(e)
		}
	}
	conflicting := j
	conflicting.Maintenance = true
	if e := s.CreateClientUpdateJob(ctx, conflicting, "operator", "", now); e == nil {
		t.Fatal("conflicting idempotency accepted")
	}
	second := j
	second.ID = "update-contract-0002"
	if e := s.CreateClientUpdateJob(ctx, second, "operator", "", now); e == nil {
		t.Fatal("parallel open job accepted")
	}
	auditFailure(true)
	if e := s.ChangeClientUpdateJob(ctx, j.ID, client, clientupdate.JobDispatched, false, "", "", now); e == nil {
		t.Fatal("dispatch without audit")
	}
	auditFailure(false)
	jobs, _ := s.ClientUpdateJobs(ctx, client)
	if len(jobs) != 1 || jobs[0].State != clientupdate.JobScheduled {
		t.Fatal("audit rollback failed")
	}
	if e := s.ChangeClientUpdateJob(ctx, j.ID, "another-client", clientupdate.JobDispatched, false, "", "", now); e == nil {
		t.Fatal("foreign client dispatched")
	}
	if e := s.ChangeClientUpdateJob(ctx, j.ID, client, clientupdate.JobDispatched, false, "", "", now.Add(-time.Second)); e == nil {
		t.Fatal("early dispatch")
	}
	// Concurrent cancellation versus start must have exactly one winning state.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, state := range []clientupdate.JobState{clientupdate.JobDispatched, clientupdate.JobCancelled} {
		wg.Add(1)
		go func(state clientupdate.JobState) {
			defer wg.Done()
			errs <- s.ChangeClientUpdateJob(ctx, j.ID, client, state, false, "", "", now)
		}(state)
	}
	wg.Wait()
	close(errs)
	wins := 0
	for e := range errs {
		if e == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("start/cancel winners=%d", wins)
	}
	jobs, _ = s.ClientUpdateJobs(ctx, client)
	if jobs[0].State == clientupdate.JobDispatched {
		auditFailure(true)
		if e := s.ChangeClientUpdateJob(ctx, j.ID, client, clientupdate.JobSucceeded, true, "", "", now); e == nil {
			t.Fatal("result without audit")
		}
		auditFailure(false)
		for i := 0; i < 2; i++ {
			if e := s.ChangeClientUpdateJob(ctx, j.ID, client, clientupdate.JobSucceeded, true, "", "", now.Add(2*time.Hour)); e != nil {
				t.Fatal(e)
			}
		}
		if e := s.ChangeClientUpdateJob(ctx, j.ID, client, clientupdate.JobFailed, true, "", "", now); e == nil {
			t.Fatal("conflicting result accepted")
		}
	}
	second.NotBefore = now.Add(time.Hour).Unix()
	second.ExpiresAt = now.Add(2 * time.Hour).Unix()
	if e := s.CreateClientUpdateJob(ctx, second, "operator", "", now); e != nil {
		t.Fatal(e)
	}
	if e := s.ChangeClientUpdateJob(ctx, second.ID, client, clientupdate.JobDispatched, false, "", "", now.Add(2*time.Hour)); e == nil {
		t.Fatal("late dispatch accepted")
	}
	third := second
	third.ID = "update-contract-0003"
	third.NotBefore = now.Add(2 * time.Hour).Unix()
	third.ExpiresAt = now.Add(3 * time.Hour).Unix()
	if e := s.CreateClientUpdateJob(ctx, third, "operator", "", now.Add(2*time.Hour)); e != nil {
		t.Fatal("offline expiry did not free client", e)
	}
	if e := s.ChangeClientUpdateJob(ctx, third.ID, client, clientupdate.JobCancelled, false, "operator", "", now.Add(2*time.Hour)); e != nil {
		t.Fatal(e)
	}
}
func TestSQLiteUpdateJobContract(t *testing.T) {
	s, e := Open(":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	testUpdateJobContract(t, s, func(id string) {
		if _, e := s.DB.Exec(`UPDATE clients SET auth_mode='certificate_preferred' WHERE client_id=?`, id); e != nil {
			t.Fatal(e)
		}
	}, func(fail bool) {
		q := `DROP TRIGGER IF EXISTS update_job_audit_failure`
		if fail {
			q = `CREATE TRIGGER update_job_audit_failure BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END`
		}
		if _, e := s.DB.Exec(q); e != nil {
			t.Fatal(e)
		}
	})
}
func TestSQLiteConcurrentUpdateCreation(t *testing.T) {
	s, e := Open(":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := t.Context()
	s.CreateClient(ctx, "parallel-update-client", "hash")
	s.DB.Exec(`UPDATE clients SET auth_mode='certificate_preferred'`)
	var wg sync.WaitGroup
	wins := make(chan bool, 8)
	now := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			j := ClientUpdateJob{ID: fmt.Sprintf("parallel-job-%016d", i), ClientID: "parallel-update-client", ReleaseID: "approved-release-0001", ReleaseVersion: "1.13.0", PackageSHA256: strings.Repeat("a", 64), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
			wins <- s.CreateClientUpdateJob(ctx, j, "operator", "", now) == nil
		}(i)
	}
	wg.Wait()
	close(wins)
	n := 0
	for win := range wins {
		if win {
			n++
		}
	}
	if n != 1 {
		t.Fatal("multiple open jobs", n)
	}
}
