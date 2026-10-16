package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) CreateOIDCClientWithAudit(ctx context.Context, clientID, secretHash, redirectURIs, scopes, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO oidc_clients(client_id,secret_hash,redirect_uris,scopes) VALUES($1,$2,$3,$4)`, clientID, secretHash, redirectURIs, scopes); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES($1,$2,$3,$4)`, "oidc_client_created", clientID, true, ip)
		return err
	})
}

func (s *PostgresStore) RotateOIDCClientSecretWithAudit(ctx context.Context, clientID, secretHash, ip string) error {
	return s.updateOIDCClientWithAudit(ctx, clientID, ip, "oidc_client_secret_rotated", `UPDATE oidc_clients SET secret_hash=$1,updated_at=now() WHERE client_id=$2`, secretHash, clientID)
}

func (s *PostgresStore) SetOIDCClientEnabledWithAudit(ctx context.Context, clientID string, enabled bool, ip string) error {
	if enabled {
		return s.updateOIDCClientWithAudit(ctx, clientID, ip, "oidc_client_enabled", `UPDATE oidc_clients SET enabled=$1,updated_at=now() WHERE client_id=$2`, true, clientID)
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `UPDATE oidc_clients SET enabled=FALSE,updated_at=now() WHERE client_id=$1`, clientID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		if _, err := tx.Exec(ctx, `UPDATE oidc_sessions SET revoked_at=now() WHERE client_id=$1 AND revoked_at IS NULL`, clientID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES($1,$2,$3,$4)`, "oidc_client_disabled", clientID, true, ip)
		return err
	})
}

func (s *PostgresStore) updateOIDCClientWithAudit(ctx context.Context, clientID, ip, event, query string, args ...any) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES($1,$2,$3,$4)`, event, clientID, true, ip)
		return err
	})
}

func (s *PostgresStore) EnsureOIDCSubjectWithAudit(ctx context.Context, userID int64, ip string) (string, error) {
	if err := validateAuditIP(ip); err != nil {
		return "", err
	}
	var subject string
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var username string
		if err := tx.QueryRow(ctx, `SELECT oidc_subject,username FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&subject, &username); err != nil {
			return postgresNotFound(err)
		}
		if subject != "" {
			return nil
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		subject = base64.RawURLEncoding.EncodeToString(raw)
		if _, err := tx.Exec(ctx, `UPDATE users SET oidc_subject=$1,updated_at=now() WHERE id=$2`, subject, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES($1,$2,$3,$4)`, "oidc_subject_created", username, true, ip)
		return err
	})
	return subject, err
}
