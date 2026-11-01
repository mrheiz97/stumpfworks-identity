package clientupdate

import (
	"errors"
	"time"
)

// JobState is the durable server-side update lifecycle. A dispatched job must
// never be automatically requeued: a lost response does not prove nonexecution.
type JobState string

const (
	JobScheduled  JobState = "scheduled"
	JobDispatched JobState = "dispatched"
	JobSucceeded  JobState = "succeeded"
	JobFailed     JobState = "failed"
	JobCancelled  JobState = "cancelled"
	JobExpired    JobState = "expired"
)

// JobWindow binds execution permission to an explicit bounded interval.
type JobWindow struct {
	NotBefore          time.Time
	ExpiresAt          time.Time
	LightDMMaintenance bool
}

func (w JobWindow) Validate(now time.Time, requiresLightDM bool) error {
	if w.NotBefore.IsZero() || w.ExpiresAt.IsZero() || !w.ExpiresAt.After(w.NotBefore) || w.ExpiresAt.Sub(w.NotBefore) > 24*time.Hour || !w.ExpiresAt.After(now) || w.NotBefore.After(now.Add(90*24*time.Hour)) {
		return errors.New("invalid update execution window")
	}
	if requiresLightDM && !w.LightDMMaintenance {
		return errors.New("LightDM maintenance authorization required")
	}
	return nil
}

// Transition validates lifecycle changes independently of database dialect.
// Stores must additionally compare the old state atomically and commit audit
// in the same transaction. Repeated identical terminal reports are idempotent.
func (w JobWindow) Transition(from, to JobState, now time.Time) error {
	if from == to && (from == JobSucceeded || from == JobFailed || from == JobCancelled || from == JobExpired) {
		return nil
	}
	if from == JobScheduled {
		if to == JobCancelled {
			return nil
		}
		if to == JobExpired && !now.Before(w.ExpiresAt) {
			return nil
		}
		if to == JobDispatched && !now.Before(w.NotBefore) && now.Before(w.ExpiresAt) {
			return nil
		}
	}
	if from == JobDispatched && (to == JobSucceeded || to == JobFailed) {
		return nil
	}
	return errors.New("invalid update job transition")
}
