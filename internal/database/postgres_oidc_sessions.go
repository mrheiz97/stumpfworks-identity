package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const postgresOIDCSessionColumns = "s.session_id,s.access_token_hash,s.client_id,s.user_id,u.username,u.oidc_subject,s.scope,s.issued_at,s.expires_at,s.revoked_at"

func scanPostgresOIDCSession(row pgx.Row) (OIDCSession, error) {
	var session OIDCSession
	err := row.Scan(&session.SessionID, &session.AccessTokenHash, &session.ClientID, &session.UserID, &session.Username, &session.Subject, &session.Scope, &session.IssuedAt, &session.ExpiresAt, &session.RevokedAt)
	return session, postgresNotFound(err)
}

func (s *PostgresStore) ConsumeOIDCCodeWithSessionAudit(ctx context.Context, hash, clientID, redirectURI string, now time.Time, session OIDCSession, ip string) (OIDCCode, error) {
	if err := validateAuditIP(ip); err != nil {
		return OIDCCode{}, err
	}
	if session.SessionID == "" || session.AccessTokenHash == "" || !session.ExpiresAt.After(now) {
		return OIDCCode{}, errors.New("invalid OIDC session")
	}
	var code OIDCCode
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		code, err = scanPostgresOIDCCode(tx.QueryRow(ctx, `UPDATE oidc_codes SET consumed_at=$1 WHERE code_hash=$2 AND client_id=$3 AND redirect_uri=$4 AND consumed_at IS NULL AND expires_at>=$1 RETURNING code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at`, now.UTC(), hash, clientID, redirectURI))
		if err != nil {
			return err
		}
		var username string
		if err := tx.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, code.UserID).Scan(&username); err != nil {
			return postgresNotFound(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM oidc_sessions WHERE expires_at<$1`, now.Add(-7*24*time.Hour).UTC()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO oidc_sessions(session_id,access_token_hash,client_id,user_id,scope,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, session.SessionID, session.AccessTokenHash, code.ClientID, code.UserID, code.Scope, now.UTC(), session.ExpiresAt.UTC()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,client_id,success,ip_address) VALUES($1,$2,$3,$4,$5)`, "oidc_token_issued", username, clientID, true, ip)
		return err
	})
	return code, err
}

func (s *PostgresStore) OIDCSessionByTokenHash(ctx context.Context, tokenHash, clientID string, now time.Time) (OIDCSession, error) {
	return scanPostgresOIDCSession(s.pool.Native().QueryRow(ctx, `SELECT `+postgresOIDCSessionColumns+` FROM oidc_sessions s JOIN users u ON u.id=s.user_id JOIN oidc_clients c ON c.client_id=s.client_id WHERE s.access_token_hash=$1 AND s.client_id=$2 AND s.revoked_at IS NULL AND s.expires_at>$3 AND c.enabled=TRUE`, tokenHash, clientID, now.UTC()))
}

func (s *PostgresStore) OIDCSessions(ctx context.Context, now time.Time) ([]OIDCSession, error) {
	rows, err := s.pool.Native().Query(ctx, `SELECT `+postgresOIDCSessionColumns+` FROM oidc_sessions s JOIN users u ON u.id=s.user_id ORDER BY s.issued_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []OIDCSession
	for rows.Next() {
		session, err := scanPostgresOIDCSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (s *PostgresStore) RevokeOIDCSessionWithAudit(ctx context.Context, sessionID, ip, reason string) error {
	return s.revokeOIDCSessionWithAudit(ctx, "s.session_id=$1", "session_id=$1", []any{sessionID}, ip, reason)
}

func (s *PostgresStore) RevokeOIDCSessionByTokenHashWithAudit(ctx context.Context, tokenHash, clientID, ip string) error {
	return s.revokeOIDCSessionWithAudit(ctx, "s.access_token_hash=$1 AND s.client_id=$2", "access_token_hash=$1 AND client_id=$2", []any{tokenHash, clientID}, ip, "client_revocation")
}

func (s *PostgresStore) RevokeOIDCSessionsByUserWithAudit(ctx context.Context, username, ip string) (int64, error) {
	var canonical string
	if err := s.pool.Native().QueryRow(ctx, `SELECT username FROM users WHERE `+postgresFoldUsername+`=`+postgresFoldArgument, username).Scan(&canonical); err != nil {
		return 0, postgresNotFound(err)
	}
	return s.revokeOIDCSessionsBulkWithAudit(ctx, `user_id=(SELECT id FROM users WHERE lower(username)=lower($2))`, []any{canonical}, "oidc_user_sessions_revoked", canonical, "", ip, "admin_user_revocation")
}

func (s *PostgresStore) RevokeOIDCSessionsByClientWithAudit(ctx context.Context, clientID, ip string) (int64, error) {
	return s.revokeOIDCSessionsBulkWithAudit(ctx, `client_id=$2`, []any{clientID}, "oidc_client_sessions_revoked", "", clientID, ip, "admin_client_revocation")
}

func (s *PostgresStore) RevokeAllOIDCSessionsWithAudit(ctx context.Context, ip string) (int64, error) {
	return s.revokeOIDCSessionsBulkWithAudit(ctx, `TRUE`, nil, "oidc_all_sessions_revoked", "", "", ip, "admin_global_revocation")
}

func (s *PostgresStore) revokeOIDCSessionsBulkWithAudit(ctx context.Context, predicate string, args []any, event, username, clientID, ip, reason string) (int64, error) {
	if err := validateAuditIP(ip); err != nil {
		return 0, err
	}
	var count int64
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		updateArgs := append([]any{time.Now().UTC()}, args...)
		result, err := tx.Exec(ctx, `UPDATE oidc_sessions SET revoked_at=$1 WHERE `+predicate+` AND revoked_at IS NULL AND expires_at>now()`, updateArgs...)
		if err != nil {
			return err
		}
		count = result.RowsAffected()
		if count == 0 {
			return pgx.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5,$6)`, event, username, clientID, true, ip, fmt.Sprintf("%s,count=%d", reason, count))
		return err
	})
	return count, err
}

func (s *PostgresStore) revokeOIDCSessionWithAudit(ctx context.Context, selectPredicate, updatePredicate string, args []any, ip, reason string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var sessionID, username, clientID string
		if err := tx.QueryRow(ctx, `SELECT s.session_id,u.username,s.client_id FROM oidc_sessions s JOIN users u ON u.id=s.user_id WHERE `+selectPredicate+` AND s.revoked_at IS NULL FOR UPDATE`, args...).Scan(&sessionID, &username, &clientID); err != nil {
			return postgresNotFound(err)
		}
		updateArgs := append(append([]any{}, args...), time.Now().UTC())
		result, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE oidc_sessions SET revoked_at=$%d WHERE %s AND revoked_at IS NULL`, len(updateArgs), updatePredicate), updateArgs...)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return pgx.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5,$6)`, "oidc_session_revoked", username, clientID, true, ip, reason)
		return err
	})
}
