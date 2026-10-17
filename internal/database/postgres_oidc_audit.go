package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func scanPostgresOIDCCode(row pgx.Row) (OIDCCode, error) {
	var code OIDCCode
	err := row.Scan(&code.CodeHash, &code.ClientID, &code.UserID, &code.RedirectURI, &code.Scope, &code.Nonce, &code.CodeChallenge, &code.ExpiresAt)
	return code, postgresNotFound(err)
}

func (s *PostgresStore) CreateOIDCCodeWithAudit(ctx context.Context, code OIDCCode, username, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM oidc_codes WHERE code_hash IN (SELECT code_hash FROM oidc_codes WHERE expires_at<now() LIMIT 100)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO oidc_codes(code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.Scope, code.Nonce, code.CodeChallenge, code.ExpiresAt.UTC()); err != nil {
			return err
		}
		var storedUsername string
		if err := tx.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, code.UserID).Scan(&storedUsername); err != nil {
			return postgresNotFound(err)
		}
		if storedUsername != username {
			return errors.New("OIDC audit identity mismatch")
		}
		for _, event := range []Audit{
			{EventType: "oidc_login", Username: storedUsername, ClientID: code.ClientID, Success: true, IPAddress: ip},
			{EventType: "oidc_consent", Username: storedUsername, ClientID: code.ClientID, Success: true, IPAddress: ip, Details: code.Scope},
			{EventType: "oidc_code_issued", Username: storedUsername, ClientID: code.ClientID, Success: true, IPAddress: ip},
		} {
			if _, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,badge_id,username,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5,$6,$7)`, event.EventType, event.BadgeID, event.Username, event.ClientID, event.Success, event.IPAddress, event.Details); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *PostgresStore) OIDCCodeForExchange(ctx context.Context, hash, clientID, redirectURI string, now time.Time) (OIDCCode, error) {
	return scanPostgresOIDCCode(s.pool.Native().QueryRow(ctx, `SELECT code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at FROM oidc_codes WHERE code_hash=$1 AND client_id=$2 AND redirect_uri=$3 AND consumed_at IS NULL AND expires_at>=$4`, hash, clientID, redirectURI, now.UTC()))
}

func (s *PostgresStore) ConsumeOIDCCodeWithAudit(ctx context.Context, hash, clientID, redirectURI string, now time.Time, ip string) (OIDCCode, error) {
	if err := validateAuditIP(ip); err != nil {
		return OIDCCode{}, err
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
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,badge_id,username,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5,$6,$7)`, "oidc_token_issued", "", username, clientID, true, ip, "")
		return err
	})
	if err != nil {
		return OIDCCode{}, err
	}
	return code, nil
}
