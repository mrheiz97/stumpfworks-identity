package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (s *Store) SetUserPINWithAudit(ctx context.Context, userID int64, hash, eventType, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var username string
	if err := tx.QueryRowContext(ctx, `SELECT username FROM users WHERE id=?`, userID).Scan(&username); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET pin_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, hash, userID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES(?,?,?,?)`, eventType, username, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateSelfServiceSessionWithAudit(ctx context.Context, id, username string, expiresAt time.Time, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO self_service_sessions(id,username,expires_at) VALUES(?,?,?)`, id, username, expiresAt.UTC()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES(?,?,?,?)`, "self_service_login", username, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeOtherSelfServiceSessionsWithAudit(ctx context.Context, username, currentID, ip string) (int64, error) {
	if err := validateAuditIP(ip); err != nil {
		return 0, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE self_service_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE lower(username)=lower(?) AND id<>? AND revoked_at IS NULL AND expires_at>=CURRENT_TIMESTAMP`, username, currentID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address,details) VALUES(?,?,?,?,?)`, "self_service_sessions_revoked", username, true, ip, fmt.Sprintf("count=%d", count)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) RevokeSelfServiceSessionWithAudit(ctx context.Context, id, username, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE self_service_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND lower(username)=lower(?) AND revoked_at IS NULL`, id, username)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES(?,?,?,?)`, "self_service_logout", username, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}
