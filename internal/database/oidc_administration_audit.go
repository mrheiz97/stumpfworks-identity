package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
)

func (s *Store) CreateOIDCClientWithAudit(ctx context.Context, clientID, secretHash, redirectURIs, scopes, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO oidc_clients(client_id,secret_hash,redirect_uris,scopes) VALUES(?,?,?,?)`, clientID, secretHash, redirectURIs, scopes); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES(?,?,?,?)`, "oidc_client_created", clientID, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RotateOIDCClientSecretWithAudit(ctx context.Context, clientID, secretHash, ip string) error {
	return s.updateOIDCClientWithAudit(ctx, clientID, ip, "oidc_client_secret_rotated", `UPDATE oidc_clients SET secret_hash=?,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, secretHash, clientID)
}

func (s *Store) SetOIDCClientEnabledWithAudit(ctx context.Context, clientID string, enabled bool, ip string) error {
	if enabled {
		return s.updateOIDCClientWithAudit(ctx, clientID, ip, "oidc_client_enabled", `UPDATE oidc_clients SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, true, clientID)
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE oidc_clients SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, clientID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oidc_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE client_id=? AND revoked_at IS NULL`, clientID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES(?,?,?,?)`, "oidc_client_disabled", clientID, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) updateOIDCClientWithAudit(ctx context.Context, clientID, ip, event, query string, args ...any) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES(?,?,?,?)`, event, clientID, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) EnsureOIDCSubjectWithAudit(ctx context.Context, userID int64, ip string) (string, error) {
	if err := validateAuditIP(ip); err != nil {
		return "", err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var subject, username string
	if err := tx.QueryRowContext(ctx, `SELECT oidc_subject,username FROM users WHERE id=?`, userID).Scan(&subject, &username); err != nil {
		return "", err
	}
	if subject != "" {
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return subject, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	subject = base64.RawURLEncoding.EncodeToString(raw)
	result, err := tx.ExecContext(ctx, `UPDATE users SET oidc_subject=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND oidc_subject=''`, subject, userID)
	if err != nil {
		return "", err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return "", sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES(?,?,?,?)`, "oidc_subject_created", username, true, ip); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return subject, nil
}
