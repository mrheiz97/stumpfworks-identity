package database

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
	"github.com/jackc/pgx/v5"
)

// Integer UTC seconds keep scheduling identical across database dialects.
const clientUpdateJobsSchema = `CREATE TABLE IF NOT EXISTS client_update_jobs (
 id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 16 AND 64), client_id TEXT NOT NULL REFERENCES clients(client_id),
 release_id TEXT NOT NULL CHECK(length(release_id) BETWEEN 16 AND 64), release_version TEXT NOT NULL CHECK(length(release_version) BETWEEN 1 AND 64), package_sha256 TEXT NOT NULL CHECK(length(package_sha256)=64),
 not_before BIGINT NOT NULL, expires_at BIGINT NOT NULL, maintenance BOOLEAN NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('scheduled','dispatched','succeeded','failed','cancelled','expired')),
 rollback_available BOOLEAN NOT NULL DEFAULT FALSE, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
 CHECK(expires_at>not_before AND expires_at-not_before<=86400));
 CREATE UNIQUE INDEX IF NOT EXISTS idx_client_update_one_open ON client_update_jobs(client_id) WHERE state IN ('scheduled','dispatched');`

type ClientUpdateJob struct {
	ID                string                `json:"id"`
	ClientID          string                `json:"client_id"`
	ReleaseID         string                `json:"release_id"`
	ReleaseVersion    string                `json:"release_version"`
	PackageSHA256     string                `json:"package_sha256"`
	NotBefore         int64                 `json:"not_before"`
	ExpiresAt         int64                 `json:"expires_at"`
	Maintenance       bool                  `json:"maintenance"`
	State             clientupdate.JobState `json:"state"`
	RollbackAvailable bool                  `json:"rollback_available"`
	CreatedAt         int64                 `json:"created_at"`
	UpdatedAt         int64                 `json:"updated_at"`
}

var updateIdentifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,64}$`)

func ValidUpdateIdentifier(s string) bool { return updateIdentifier.MatchString(s) }

const updateJobColumns = `id,client_id,release_id,release_version,package_sha256,not_before,expires_at,maintenance,state,rollback_available,created_at,updated_at`

type jobRow interface{ Scan(...any) error }

func scanUpdateJob(row jobRow) (j ClientUpdateJob, err error) {
	err = row.Scan(&j.ID, &j.ClientID, &j.ReleaseID, &j.ReleaseVersion, &j.PackageSHA256, &j.NotBefore, &j.ExpiresAt, &j.Maintenance, &j.State, &j.RollbackAvailable, &j.CreatedAt, &j.UpdatedAt)
	return j, postgresNotFound(err)
}

type jobTransaction struct {
	exec func(string, ...any) (int64, error)
	row  func(string, ...any) jobRow
}

func (s *Store) updateJobTransaction(ctx context.Context, fn func(jobTransaction) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	err = fn(jobTransaction{exec: func(q string, a ...any) (int64, error) {
		r, e := tx.ExecContext(ctx, q, a...)
		if e != nil {
			return 0, e
		}
		return r.RowsAffected()
	}, row: func(q string, a ...any) jobRow { return tx.QueryRowContext(ctx, q, a...) }})
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *PostgresStore) updateJobTransaction(ctx context.Context, fn func(jobTransaction) error) error {
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		return fn(jobTransaction{exec: func(q string, a ...any) (int64, error) { r, e := tx.Exec(ctx, q, a...); return r.RowsAffected(), e }, row: func(q string, a ...any) jobRow { return tx.QueryRow(ctx, q, a...) }})
	})
}
func createUpdateJob(tx jobTransaction, j ClientUpdateJob, actor, ip string, now time.Time) error {
	if !ValidUpdateIdentifier(j.ID) || !ValidUpdateIdentifier(j.ReleaseID) || len(j.ClientID) > 64 || j.ClientID == "" || len(actor) > 128 {
		return errors.New("invalid update job")
	}
	digest, e := hex.DecodeString(j.PackageSHA256)
	if e != nil || len(digest) != 32 {
		return errors.New("invalid package digest")
	}
	if err := (clientupdate.JobWindow{NotBefore: time.Unix(j.NotBefore, 0), ExpiresAt: time.Unix(j.ExpiresAt, 0), LightDMMaintenance: j.Maintenance}).Validate(now, false); err != nil {
		return err
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	var enabled bool
	var mode string
	if err := tx.row(`SELECT enabled,auth_mode FROM clients WHERE client_id=$1`, j.ClientID).Scan(&enabled, &mode); err != nil {
		return err
	}
	if !enabled || mode == ClientAuthTokenOnly {
		return errors.New("device certificate required")
	}
	// A repeated form submission after a lost commit response is a no-op only
	// when the complete immutable request agrees.
	old, err := scanUpdateJob(tx.row(`SELECT `+updateJobColumns+` FROM client_update_jobs WHERE id=$1`, j.ID))
	if err == nil {
		if old.ClientID == j.ClientID && old.ReleaseID == j.ReleaseID && old.ReleaseVersion == j.ReleaseVersion && old.PackageSHA256 == j.PackageSHA256 && old.NotBefore == j.NotBefore && old.ExpiresAt == j.ExpiresAt && old.Maintenance == j.Maintenance {
			return nil
		}
		return errors.New("conflicting update request")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	previous, previousErr := scanUpdateJob(tx.row(`SELECT `+updateJobColumns+` FROM client_update_jobs WHERE client_id=$1 AND state='scheduled' AND expires_at<=$2`, j.ClientID, now.Unix()))
	if previousErr == nil {
		if err = changeUpdateJob(tx, previous.ID, j.ClientID, clientupdate.JobExpired, false, actor, ip, now); err != nil {
			return err
		}
	} else if !errors.Is(previousErr, sql.ErrNoRows) {
		return previousErr
	}
	_, err = tx.exec(`INSERT INTO client_update_jobs(`+updateJobColumns+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'scheduled',FALSE,$9,$9)`, j.ID, j.ClientID, j.ReleaseID, j.ReleaseVersion, j.PackageSHA256, j.NotBefore, j.ExpiresAt, j.Maintenance, now.Unix())
	if err != nil {
		return err
	}
	_, err = tx.exec(`INSERT INTO audit_log(event_type,client_id,username,success,ip_address,details) VALUES('client_update_scheduled',$1,$2,TRUE,$3,$4)`, j.ClientID, actor, ip, "job="+j.ID)
	return err
}
func changeUpdateJob(tx jobTransaction, id, client string, to clientupdate.JobState, rollback bool, actor, ip string, now time.Time) error {
	if !ValidUpdateIdentifier(id) || len(actor) > 128 {
		return errors.New("invalid job identity")
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	j, err := scanUpdateJob(tx.row(`SELECT `+updateJobColumns+` FROM client_update_jobs WHERE id=$1 AND client_id=$2`, id, client))
	if err != nil {
		return err
	}
	if j.State == to {
		if j.RollbackAvailable != rollback {
			return errors.New("conflicting result")
		}
		return nil
	}
	w := clientupdate.JobWindow{NotBefore: time.Unix(j.NotBefore, 0), ExpiresAt: time.Unix(j.ExpiresAt, 0)}
	if err = w.Transition(j.State, to, now); err != nil {
		return err
	}
	if to == clientupdate.JobDispatched {
		var enabled bool
		var mode string
		if err = tx.row(`SELECT enabled,auth_mode FROM clients WHERE client_id=$1`, client).Scan(&enabled, &mode); err != nil {
			return err
		}
		if !enabled || mode == ClientAuthTokenOnly {
			return errors.New("device unavailable")
		}
	}
	changed, err := tx.exec(`UPDATE client_update_jobs SET state=$1,rollback_available=$2,updated_at=$3 WHERE id=$4 AND client_id=$5 AND state=$6`, to, rollback, now.Unix(), id, client, j.State)
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("concurrent job transition")
	}
	_, err = tx.exec(`INSERT INTO audit_log(event_type,client_id,username,success,ip_address,details) VALUES($1,$2,$3,TRUE,$4,$5)`, "client_update_"+string(to), client, actor, ip, "job="+id)
	return err
}
func (s *Store) CreateClientUpdateJob(ctx context.Context, j ClientUpdateJob, actor, ip string, now time.Time) error {
	return s.updateJobTransaction(ctx, func(tx jobTransaction) error { return createUpdateJob(tx, j, actor, ip, now) })
}
func (s *PostgresStore) CreateClientUpdateJob(ctx context.Context, j ClientUpdateJob, actor, ip string, now time.Time) error {
	return s.updateJobTransaction(ctx, func(tx jobTransaction) error { return createUpdateJob(tx, j, actor, ip, now) })
}
func (s *Store) ChangeClientUpdateJob(ctx context.Context, id, client string, to clientupdate.JobState, rollback bool, actor, ip string, now time.Time) error {
	return s.updateJobTransaction(ctx, func(tx jobTransaction) error { return changeUpdateJob(tx, id, client, to, rollback, actor, ip, now) })
}
func (s *PostgresStore) ChangeClientUpdateJob(ctx context.Context, id, client string, to clientupdate.JobState, rollback bool, actor, ip string, now time.Time) error {
	return s.updateJobTransaction(ctx, func(tx jobTransaction) error { return changeUpdateJob(tx, id, client, to, rollback, actor, ip, now) })
}
func (s *Store) ClientUpdateJobs(ctx context.Context, client string) ([]ClientUpdateJob, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+updateJobColumns+` FROM client_update_jobs WHERE ($1='' OR client_id=$1) ORDER BY created_at DESC,id DESC LIMIT 200`, client)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientUpdateJob{}
	for rows.Next() {
		j, e := scanUpdateJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) ClientUpdateJob(ctx context.Context, id string) (ClientUpdateJob, error) {
	return scanUpdateJob(s.DB.QueryRowContext(ctx, `SELECT `+updateJobColumns+` FROM client_update_jobs WHERE id=$1`, id))
}
func (s *PostgresStore) ClientUpdateJob(ctx context.Context, id string) (ClientUpdateJob, error) {
	return scanUpdateJob(s.pool.Native().QueryRow(ctx, `SELECT `+updateJobColumns+` FROM client_update_jobs WHERE id=$1`, id))
}
func (s *PostgresStore) ClientUpdateJobs(ctx context.Context, client string) ([]ClientUpdateJob, error) {
	rows, err := s.pool.Native().Query(ctx, `SELECT `+updateJobColumns+` FROM client_update_jobs WHERE ($1='' OR client_id=$1) ORDER BY created_at DESC,id DESC LIMIT 200`, client)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientUpdateJob{}
	for rows.Next() {
		j, e := scanUpdateJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
