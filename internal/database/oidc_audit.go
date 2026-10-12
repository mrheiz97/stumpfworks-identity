package database

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"time"
)

func validateAuditIP(ip string) error {
	if ip != "" && net.ParseIP(ip) == nil {
		return errors.New("audit IP must be an address or empty")
	}
	return nil
}

func scanSQLiteOIDCCode(row *sql.Row) (OIDCCode, error) {
	var code OIDCCode
	err := row.Scan(&code.CodeHash, &code.ClientID, &code.UserID, &code.RedirectURI, &code.Scope, &code.Nonce, &code.CodeChallenge, &code.ExpiresAt)
	return code, err
}

// CreateOIDCCodeWithAudit makes the authorization result and all three success
// events visible together. A failed audit insert leaves no redeemable code.
func (s *Store) CreateOIDCCodeWithAudit(ctx context.Context, code OIDCCode, username, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_codes WHERE code_hash IN (SELECT code_hash FROM oidc_codes WHERE expires_at<CURRENT_TIMESTAMP LIMIT 100)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oidc_codes(code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at) VALUES(?,?,?,?,?,?,?,?)`, code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.Scope, code.Nonce, code.CodeChallenge, code.ExpiresAt.UTC()); err != nil {
		return err
	}
	var storedUsername string
	if err := tx.QueryRowContext(ctx, `SELECT username FROM users WHERE id=?`, code.UserID).Scan(&storedUsername); err != nil {
		return err
	}
	if storedUsername != username {
		return errors.New("OIDC audit identity mismatch")
	}
	for _, event := range []Audit{
		{EventType: "oidc_login", Username: storedUsername, ClientID: code.ClientID, Success: true, IPAddress: ip},
		{EventType: "oidc_consent", Username: storedUsername, ClientID: code.ClientID, Success: true, IPAddress: ip, Details: code.Scope},
		{EventType: "oidc_code_issued", Username: storedUsername, ClientID: code.ClientID, Success: true, IPAddress: ip},
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,client_id,success,ip_address,details) VALUES(?,?,?,?,?,?,?)`, event.EventType, event.BadgeID, event.Username, event.ClientID, event.Success, event.IPAddress, event.Details); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) OIDCCodeForExchange(ctx context.Context, hash, clientID, redirectURI string, now time.Time) (OIDCCode, error) {
	return scanSQLiteOIDCCode(s.DB.QueryRowContext(ctx, `SELECT code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at FROM oidc_codes WHERE code_hash=? AND client_id=? AND redirect_uri=? AND consumed_at IS NULL AND expires_at>=?`, hash, clientID, redirectURI, now.UTC()))
}

// ConsumeOIDCCodeWithAudit is the final token issuance commit. Callers may
// prepare signed token material first, but must not return it until this wins.
func (s *Store) ConsumeOIDCCodeWithAudit(ctx context.Context, hash, clientID, redirectURI string, now time.Time, ip string) (OIDCCode, error) {
	if err := validateAuditIP(ip); err != nil {
		return OIDCCode{}, err
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,client_id,success,ip_address,details) VALUES(?,?,?,?,?,?,?)`, "oidc_token_issued", "", username, clientID, true, ip, ""); err != nil {
		return OIDCCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return OIDCCode{}, err
	}
	return code, nil
}
