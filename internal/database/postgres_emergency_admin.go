package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) CreateEmergencyAdminGrantWithAudit(ctx context.Context, grant EmergencyAdminGrant, ip string) error {
	if err := validateEmergencyAdminGrant(grant); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO emergency_admin_grants(id,token_hash,created_at,expires_at) VALUES($1,$2,$3,$4)`, grant.ID, grant.TokenHash, grant.CreatedAt.UTC(), grant.ExpiresAt.UTC()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,success,ip_address) VALUES($1,$2,$3)`, "emergency_admin_grant_created", true, ip)
		return err
	})
}

func (s *PostgresStore) ConsumeEmergencyAdminGrantWithAudit(ctx context.Context, tokenHash, sessionHash string, now time.Time, ip string) (EmergencyAdminGrant, error) {
	if len(tokenHash) != 64 || len(sessionHash) != 64 {
		return EmergencyAdminGrant{}, errors.New("invalid emergency grant proof")
	}
	var grant EmergencyAdminGrant
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		grant, err = scanEmergencyAdmin(tx.QueryRow(ctx, `UPDATE emergency_admin_grants SET session_hash=$1,consumed_at=$2 WHERE token_hash=$3 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>$2 RETURNING `+emergencyAdminColumns, sessionHash, now.UTC(), tokenHash))
		if err != nil {
			return postgresNotFound(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,success,ip_address) VALUES($1,$2,$3)`, "emergency_admin_login", true, ip)
		return err
	})
	return grant, err
}

func (s *PostgresStore) ActiveEmergencyAdminSession(ctx context.Context, sessionHash string, now time.Time) (EmergencyAdminGrant, error) {
	grant, err := scanEmergencyAdmin(s.pool.Native().QueryRow(ctx, `SELECT `+emergencyAdminColumns+` FROM emergency_admin_grants WHERE session_hash=$1 AND consumed_at IS NOT NULL AND revoked_at IS NULL AND expires_at>$2`, sessionHash, now.UTC()))
	return grant, postgresNotFound(err)
}

func (s *PostgresStore) EmergencyAdminGrants(ctx context.Context, now time.Time) ([]EmergencyAdminGrant, error) {
	rows, err := s.pool.Native().Query(ctx, `SELECT `+emergencyAdminColumns+` FROM emergency_admin_grants WHERE expires_at>$1 ORDER BY created_at DESC`, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []EmergencyAdminGrant
	for rows.Next() {
		grant, err := scanEmergencyAdmin(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (s *PostgresStore) RevokeEmergencyAdminGrantWithAudit(ctx context.Context, id, ip string) error {
	return s.revokeEmergencyAdminWithAudit(ctx, "id", id, ip)
}

func (s *PostgresStore) RevokeEmergencyAdminSessionWithAudit(ctx context.Context, sessionHash, ip string) error {
	if len(sessionHash) != 64 {
		return errors.New("invalid emergency administrator session")
	}
	return s.revokeEmergencyAdminWithAudit(ctx, "session_hash", sessionHash, ip)
}

func (s *PostgresStore) revokeEmergencyAdminWithAudit(ctx context.Context, column, value, ip string) error {
	if column != "id" && column != "session_hash" {
		return errors.New("invalid emergency administrator selector")
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE emergency_admin_grants SET revoked_at=now() WHERE `+column+`=$1 AND revoked_at IS NULL AND expires_at>now()`, value)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return pgx.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,success,ip_address) VALUES($1,$2,$3)`, "emergency_admin_grant_revoked", true, ip)
		return err
	})
}
