package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) SetUserPINWithAudit(ctx context.Context, userID int64, hash, eventType, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var username string
		if err := tx.QueryRow(ctx, `UPDATE users SET pin_hash=$1,updated_at=now() WHERE id=$2 RETURNING username`, hash, userID).Scan(&username); err != nil {
			return postgresNotFound(err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES($1,$2,$3,$4)`, eventType, username, true, ip)
		return err
	})
}

func (s *PostgresStore) CreateSelfServiceSessionWithAudit(ctx context.Context, id, username string, expiresAt time.Time, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO self_service_sessions(id,username,expires_at) VALUES($1,$2,$3)`, id, username, expiresAt.UTC()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES($1,$2,$3,$4)`, "self_service_login", username, true, ip)
		return err
	})
}

func (s *PostgresStore) RevokeOtherSelfServiceSessionsWithAudit(ctx context.Context, username, currentID, ip string) (int64, error) {
	if err := validateAuditIP(ip); err != nil {
		return 0, err
	}
	var count int64
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, "UPDATE self_service_sessions SET revoked_at=now() WHERE "+postgresFoldUsername+"="+postgresFoldArgument+" AND id<>$2 AND revoked_at IS NULL AND expires_at>=now()", username, currentID)
		if err != nil {
			return err
		}
		count = result.RowsAffected()
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address,details) VALUES($1,$2,$3,$4,$5)`, "self_service_sessions_revoked", username, true, ip, fmt.Sprintf("count=%d", count))
		return err
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *PostgresStore) RevokeSelfServiceSessionWithAudit(ctx context.Context, id, username, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, "UPDATE self_service_sessions SET revoked_at=now() WHERE "+postgresFoldUsername+"="+postgresFoldArgument+" AND id=$2 AND revoked_at IS NULL", username, id)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return pgx.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES($1,$2,$3,$4)`, "self_service_logout", username, true, ip)
		return err
	})
}
