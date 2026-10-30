package database

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	ClientAuthTokenOnly            = "token_only"
	ClientAuthCertificatePreferred = "certificate_preferred"
	ClientAuthCertificateRequired  = "certificate_required"
)

var ErrInvalidClientDeviceCredential = errors.New("invalid client device credential")

func validClientAuthMode(mode string) bool {
	return mode == ClientAuthTokenOnly || mode == ClientAuthCertificatePreferred || mode == ClientAuthCertificateRequired
}

func validPublicIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 255 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == ':' || r == '-') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validCertificateSerial(value string) bool {
	if len(value) < 1 || len(value) > 128 || strings.ToLower(value) != value || value[0] == '0' {
		return false
	}
	_, err := hex.DecodeString(strings.Repeat("0", len(value)%2) + value)
	return err == nil
}

func validateEnrollmentToken(token ClientEnrollmentToken) error {
	if !validPublicIdentifier(token.ID) || !validPublicIdentifier(token.ClientID) || !validSHA256(token.TokenHash) || token.CreatedAt.IsZero() || !token.ExpiresAt.After(token.CreatedAt) || token.ExpiresAt.Sub(token.CreatedAt) > 24*time.Hour {
		return ErrInvalidClientDeviceCredential
	}
	return nil
}

func validateDeviceCredential(credential ClientDeviceCredential) error {
	expectedURISAN := "urn:stumpfworks:identity:client:" + credential.ClientID
	if !validPublicIdentifier(credential.ID) || !validPublicIdentifier(credential.ClientID) || !validSHA256(credential.FingerprintSHA256) || !validCertificateSerial(credential.Serial) || credential.URISAN != expectedURISAN || len(credential.URISAN) > 255 || !validPublicIdentifier(credential.PublicKeyAlgorithm) || !validPublicIdentifier(credential.IssuerID) || credential.IssuedAt.IsZero() || !credential.ExpiresAt.After(credential.IssuedAt) || credential.ExpiresAt.Sub(credential.IssuedAt) > 397*24*time.Hour {
		return ErrInvalidClientDeviceCredential
	}
	return nil
}

func (s *Store) RenewClientDeviceCredentialWithAudit(ctx context.Context, currentCredentialID string, now time.Time, replacement ClientDeviceCredential, ip string) error {
	if !validPublicIdentifier(currentCredentialID) || validateDeviceCredential(replacement) != nil || validateAuditIP(ip) != nil || now.IsZero() {
		return ErrInvalidClientDeviceCredential
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE client_device_credentials SET status='superseded',updated_at=? WHERE id=? AND client_id=? AND status='active' AND expires_at>?`, now.UTC(), currentCredentialID, replacement.ClientID, now.UTC())
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO client_device_credentials(id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status) VALUES(?,?,?,?,?,?,?,?,?,'active')`, replacement.ID, replacement.ClientID, replacement.FingerprintSHA256, replacement.Serial, replacement.URISAN, replacement.PublicKeyAlgorithm, replacement.IssuerID, replacement.IssuedAt.UTC(), replacement.ExpiresAt.UTC()); err != nil {
		return err
	}
	details := "credential_id=" + replacement.ID + ",supersedes=" + currentCredentialID
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES(?,?,?,?,?)`, "client_device_renewed", replacement.ClientID, true, ip, details); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateClientEnrollmentTokenWithAudit(ctx context.Context, token ClientEnrollmentToken, ip string) error {
	if validateEnrollmentToken(token) != nil || validateAuditIP(ip) != nil {
		return ErrInvalidClientDeviceCredential
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO client_enrollment_tokens(id,client_id,token_hash,created_at,expires_at) SELECT ?,client_id,?,?,? FROM clients WHERE client_id=? AND enabled=1`, token.ID, token.TokenHash, token.CreatedAt.UTC(), token.ExpiresAt.UTC(), token.ClientID, token.ClientID); err != nil {
		return err
	}
	var inserted int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM client_enrollment_tokens WHERE id=?`, token.ID).Scan(&inserted); err != nil || inserted != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES(?,?,?,?,?)`, "client_enrollment_created", token.ClientID, true, ip, "enrollment_id="+token.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) EnrollClientDeviceCredentialWithAudit(ctx context.Context, tokenHash string, now time.Time, credential ClientDeviceCredential, ip string) error {
	if !validSHA256(tokenHash) || validateDeviceCredential(credential) != nil || validateAuditIP(ip) != nil || now.IsZero() {
		return ErrInvalidClientDeviceCredential
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE client_enrollment_tokens SET consumed_at=? WHERE token_hash=? AND client_id=? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>=? AND EXISTS(SELECT 1 FROM clients WHERE client_id=? AND enabled=1)`, now.UTC(), tokenHash, credential.ClientID, now.UTC(), credential.ClientID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO client_device_credentials(id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status) VALUES(?,?,?,?,?,?,?,?,?,'active')`, credential.ID, credential.ClientID, credential.FingerprintSHA256, credential.Serial, credential.URISAN, credential.PublicKeyAlgorithm, credential.IssuerID, credential.IssuedAt.UTC(), credential.ExpiresAt.UTC()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES(?,?,?,?,?)`, "client_device_enrolled", credential.ClientID, true, ip, "credential_id="+credential.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ClientDeviceCredentials(ctx context.Context, clientID string) ([]ClientDeviceCredential, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status,revoked_at,created_at,updated_at FROM client_device_credentials WHERE client_id=? ORDER BY created_at,id`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var credentials []ClientDeviceCredential
	for rows.Next() {
		var credential ClientDeviceCredential
		if err := rows.Scan(&credential.ID, &credential.ClientID, &credential.FingerprintSHA256, &credential.Serial, &credential.URISAN, &credential.PublicKeyAlgorithm, &credential.IssuerID, &credential.IssuedAt, &credential.ExpiresAt, &credential.Status, &credential.RevokedAt, &credential.CreatedAt, &credential.UpdatedAt); err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (s *Store) ActiveClientDeviceCredential(ctx context.Context, clientID string, now time.Time) (credential ClientDeviceCredential, err error) {
	if !validPublicIdentifier(clientID) || now.IsZero() {
		return credential, ErrInvalidClientDeviceCredential
	}
	err = s.DB.QueryRowContext(ctx, `SELECT id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status,revoked_at,created_at,updated_at FROM client_device_credentials WHERE client_id=? AND status='active' AND issued_at<=? AND expires_at>?`, clientID, now.UTC(), now.UTC()).Scan(&credential.ID, &credential.ClientID, &credential.FingerprintSHA256, &credential.Serial, &credential.URISAN, &credential.PublicKeyAlgorithm, &credential.IssuerID, &credential.IssuedAt, &credential.ExpiresAt, &credential.Status, &credential.RevokedAt, &credential.CreatedAt, &credential.UpdatedAt)
	return credential, err
}

func (s *Store) RevokeClientDeviceCredentialWithAudit(ctx context.Context, clientID, credentialID, ip string, now time.Time) error {
	if !validPublicIdentifier(clientID) || !validPublicIdentifier(credentialID) || validateAuditIP(ip) != nil || now.IsZero() {
		return ErrInvalidClientDeviceCredential
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE client_device_credentials SET status='revoked',revoked_at=?,updated_at=? WHERE id=? AND client_id=? AND status='active'`, now.UTC(), now.UTC(), credentialID, clientID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES(?,?,?,?,?)`, "client_device_revoked", clientID, true, ip, "credential_id="+credentialID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetClientAuthenticationModeWithAudit(ctx context.Context, clientID, mode, ip string, now time.Time) error {
	if !validPublicIdentifier(clientID) || !validClientAuthMode(mode) || validateAuditIP(ip) != nil || now.IsZero() {
		return ErrInvalidClientDeviceCredential
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `UPDATE clients SET auth_mode=?,updated_at=? WHERE client_id=?`
	if mode != ClientAuthTokenOnly {
		query += ` AND EXISTS(SELECT 1 FROM client_device_credentials WHERE client_id=? AND status='active' AND expires_at>?)`
	}
	args := []any{mode, now.UTC(), clientID}
	if mode != ClientAuthTokenOnly {
		args = append(args, clientID, now.UTC())
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES(?,?,?,?,?)`, "client_authentication_mode_changed", clientID, true, ip, "mode="+mode); err != nil {
		return err
	}
	return tx.Commit()
}
