package clientupdate

import (
	"testing"
	"time"
)

func TestJobExecutionBoundaries(t *testing.T) {
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	w := JobWindow{NotBefore: now, ExpiresAt: now.Add(time.Hour)}
	if err := w.Validate(now, true); err == nil {
		t.Fatal("greeter without maintenance accepted")
	}
	w.LightDMMaintenance = true
	if err := w.Validate(now, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		from, to JobState
		at       time.Time
		allowed  bool
	}{
		{JobScheduled, JobDispatched, now.Add(-time.Nanosecond), false},
		{JobScheduled, JobDispatched, now, true},
		{JobScheduled, JobDispatched, w.ExpiresAt, false},
		{JobScheduled, JobExpired, w.ExpiresAt, true},
		{JobScheduled, JobCancelled, now, true},
		{JobDispatched, JobCancelled, now, false},
		{JobDispatched, JobScheduled, w.ExpiresAt, false},
		{JobDispatched, JobSucceeded, w.ExpiresAt, true},
		{JobSucceeded, JobSucceeded, w.ExpiresAt, true},
		{JobSucceeded, JobFailed, w.ExpiresAt, false},
		{JobFailed, JobScheduled, w.ExpiresAt, false},
	} {
		if got := w.Transition(tc.from, tc.to, tc.at) == nil; got != tc.allowed {
			t.Errorf("%s -> %s at %s: allowed=%v", tc.from, tc.to, tc.at, got)
		}
	}
}
