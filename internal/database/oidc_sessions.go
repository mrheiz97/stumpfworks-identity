package database

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const sqliteOIDCSessionColumns = "s.session_id,s.access_token_hash,s.client_id,s.user_id,u.username,u.oidc_subject,s.scope,s.issued_at,s.expires_at,s.revoked_at"

func scanSQLiteOIDCSession(row interface{ Scan(...any) error }) (OIDCSession, error) {
	var session OIDCSession
	err := row.Scan(&session.SessionID, &session.AccessTokenHash, &session.ClientID, &session.UserID, &session.Username, &session.Subject, &session.Scope, &session.IssuedAt, &session.ExpiresAt, &session.RevokedAt)
	return session, err
}

// ConsumeOIDCCodeWithSessionAudit publishes code consumption, the revocable
// opaque token and its success audit as one transaction.
func (s *Store) ConsumeOIDCCodeWithSessionAudit(ctx context.Context, hash, clientID, redirectURI string, now time.Time, session OIDCSession, ip string) (OIDCCode, error) {
	if err := validateAuditIP(ip); err != nil {
		return OIDCCode{}, err
	}
	if session.SessionID == "" || session.AccessTokenHash == "" || !session.ExpiresAt.After(now) {
		return OIDCCode{}, errors.New("invalid OIDC session")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return OIDCCode{}, err
	}
	defer tx.Rollback()
	code, err := scanSQLiteOIDCCode(tx.QueryRowContext(ctx, `SELECT code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at FROM oidc_codes WHERE code_hash=? AND client_id=? AND redirect_uri=? AND consumed_at IS NULL AND expires_at>=?`, hash, clientID, redirectURI, now.UTC()))
	if err != nil {
		return OIDCCode{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE oidc_codes SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL`, now.UTC(), hash)
	if err != nil {
		return OIDCCode{}, err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return OIDCCode{}, sql.ErrNoRows
	}
	var username string
	if err := tx.QueryRowContext(ctx, `SELECT username FROM users WHERE id=?`, code.UserID).Scan(&username); err != nil {
		return OIDCCode{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE expires_at<?`, now.Add(-7*24*time.Hour).UTC()); err != nil {
		return OIDCCode{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oidc_sessions(session_id,access_token_hash,client_id,user_id,scope,issued_at,expires_at) VALUES(?,?,?,?,?,?,?)`, session.SessionID, session.AccessTokenHash, code.ClientID, code.UserID, code.Scope, now.UTC(), session.ExpiresAt.UTC()); err != nil {
		return OIDCCode{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,client_id,success,ip_address) VALUES(?,?,?,?,?)`, "oidc_token_issued", username, clientID, true, ip); err != nil {
		return OIDCCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return OIDCCode{}, err
	}
	return code, nil
}

func (s *Store) OIDCSessionByTokenHash(ctx context.Context, tokenHash, clientID string, now time.Time) (OIDCSession, error) {
	return scanSQLiteOIDCSession(s.DB.QueryRowContext(ctx, `SELECT `+sqliteOIDCSessionColumns+` FROM oidc_sessions s JOIN users u ON u.id=s.user_id JOIN oidc_clients c ON c.client_id=s.client_id WHERE s.access_token_hash=? AND s.client_id=? AND s.revoked_at IS NULL AND s.expires_at>? AND c.enabled=1`, tokenHash, clientID, now.UTC()))
}

func (s *Store) OIDCSessions(ctx context.Context, now time.Time) ([]OIDCSession, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+sqliteOIDCSessionColumns+` FROM oidc_sessions s JOIN users u ON u.id=s.user_id ORDER BY s.issued_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []OIDCSession
	for rows.Next() {
		session, err := scanSQLiteOIDCSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (s *Store) RevokeOIDCSessionWithAudit(ctx context.Context, sessionID, ip, reason string) error {
	return s.revokeOIDCSessionWithAudit(ctx, `session_id=?`, sessionID, ip, reason)
}

func (s *Store) RevokeOIDCSessionByTokenHashWithAudit(ctx context.Context, tokenHash, clientID, ip string) error {
	return s.revokeOIDCSessionWithAudit(ctx, `access_token_hash=? AND client_id=?`, tokenHash, ip, "client_revocation", clientID)
}

func (s *Store) revokeOIDCSessionWithAudit(ctx context.Context, predicate string, value string, ip string, reason string, extra ...any) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	args := []any{value}
	args = append(args, extra...)
	var sessionID, username, clientID string
	query := `SELECT s.session_id,u.username,s.client_id FROM oidc_sessions s JOIN users u ON u.id=s.user_id WHERE ` + predicate + ` AND s.revoked_at IS NULL`
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&sessionID, &username, &clientID); err != nil {
		return err
	}
	updateArgs := append([]any{time.Now().UTC()}, args...)
	result, err := tx.ExecContext(ctx, `UPDATE oidc_sessions SET revoked_at=? WHERE `+predicate+` AND revoked_at IS NULL`, updateArgs...)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,client_id,success,ip_address,details) VALUES(?,?,?,?,?,?)`, "oidc_session_revoked", username, clientID, true, ip, reason); err != nil {
		return err
	}
	return tx.Commit()
}
