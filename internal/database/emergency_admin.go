package database

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const emergencyAdminColumns = "id,token_hash,COALESCE(session_hash,''),created_at,expires_at,consumed_at,revoked_at"

func scanEmergencyAdmin(row interface{ Scan(...any) error }) (EmergencyAdminGrant, error) {
	var grant EmergencyAdminGrant
	err := row.Scan(&grant.ID, &grant.TokenHash, &grant.SessionHash, &grant.CreatedAt, &grant.ExpiresAt, &grant.ConsumedAt, &grant.RevokedAt)
	return grant, err
}

func (s *Store) CreateEmergencyAdminGrantWithAudit(ctx context.Context, grant EmergencyAdminGrant, ip string) error {
	if err := validateEmergencyAdminGrant(grant); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO emergency_admin_grants(id,token_hash,created_at,expires_at) VALUES(?,?,?,?)`, grant.ID, grant.TokenHash, grant.CreatedAt.UTC(), grant.ExpiresAt.UTC()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,success,ip_address) VALUES(?,?,?)`, "emergency_admin_grant_created", true, ip); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConsumeEmergencyAdminGrantWithAudit(ctx context.Context, tokenHash, sessionHash string, now time.Time, ip string) (EmergencyAdminGrant, error) {
	if len(tokenHash) != 64 || len(sessionHash) != 64 {
		return EmergencyAdminGrant{}, errors.New("invalid emergency grant proof")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return EmergencyAdminGrant{}, err
	}
	defer tx.Rollback()
	grant, err := scanEmergencyAdmin(tx.QueryRowContext(ctx, `UPDATE emergency_admin_grants SET session_hash=?,consumed_at=? WHERE token_hash=? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>? RETURNING `+emergencyAdminColumns, sessionHash, now.UTC(), tokenHash, now.UTC()))
	if err != nil {
		return EmergencyAdminGrant{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,success,ip_address) VALUES(?,?,?)`, "emergency_admin_login", true, ip); err != nil {
		return EmergencyAdminGrant{}, err
	}
	return grant, tx.Commit()
}

func validateEmergencyAdminGrant(grant EmergencyAdminGrant) error {
	duration := grant.ExpiresAt.Sub(grant.CreatedAt)
	if len(grant.ID) < 16 || len(grant.ID) > 128 || len(grant.TokenHash) != 64 || duration < 5*time.Minute || duration > time.Hour {
		return errors.New("invalid emergency administrator grant")
	}
	return nil
}

func (s *Store) ActiveEmergencyAdminSession(ctx context.Context, sessionHash string, now time.Time) (EmergencyAdminGrant, error) {
	return scanEmergencyAdmin(s.DB.QueryRowContext(ctx, `SELECT `+emergencyAdminColumns+` FROM emergency_admin_grants WHERE session_hash=? AND consumed_at IS NOT NULL AND revoked_at IS NULL AND expires_at>?`, sessionHash, now.UTC()))
}

func (s *Store) EmergencyAdminGrants(ctx context.Context, now time.Time) ([]EmergencyAdminGrant, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+emergencyAdminColumns+` FROM emergency_admin_grants WHERE expires_at>? ORDER BY created_at DESC`, now.UTC())
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

func (s *Store) RevokeEmergencyAdminGrantWithAudit(ctx context.Context, id, ip string) error {
	return s.revokeEmergencyAdminWithAudit(ctx, "id", id, ip)
}

func (s *Store) RevokeEmergencyAdminSessionWithAudit(ctx context.Context, sessionHash, ip string) error {
	if len(sessionHash) != 64 {
		return errors.New("invalid emergency administrator session")
	}
	return s.revokeEmergencyAdminWithAudit(ctx, "session_hash", sessionHash, ip)
}

func (s *Store) revokeEmergencyAdminWithAudit(ctx context.Context, column, value, ip string) error {
	if column != "id" && column != "session_hash" {
		return errors.New("invalid emergency administrator selector")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE emergency_admin_grants SET revoked_at=CURRENT_TIMESTAMP WHERE `+column+`=? AND revoked_at IS NULL AND expires_at>CURRENT_TIMESTAMP`, value)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,success,ip_address) VALUES(?,?,?)`, "emergency_admin_grant_revoked", true, ip); err != nil {
		return err
	}
	return tx.Commit()
}
