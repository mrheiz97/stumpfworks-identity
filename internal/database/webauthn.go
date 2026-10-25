package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"time"
)

const webAuthnHandleBytes = 32

func newWebAuthnManagementID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validWebAuthnRPID(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || net.ParseIP(value) != nil || strings.ContainsAny(value, ":/ \\") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	return true
}

func validWebAuthnCredential(credential WebAuthnCredential) bool {
	name := strings.TrimSpace(credential.Name)
	return len(credential.CredentialID) >= 1 && len(credential.CredentialID) <= 4096 &&
		len(credential.ManagementID) >= 16 && len(credential.ManagementID) <= 128 &&
		credential.UserID > 0 && len(credential.PublicKey) >= 1 && len(credential.PublicKey) <= 8192 &&
		validWebAuthnRPID(credential.RPID) && len(name) >= 1 && len(name) <= 64 && name == credential.Name &&
		len(credential.Transports) <= 256 && len(credential.AttestationType) <= 64 && len(credential.AttestationFormat) <= 64 &&
		credential.Flags >= 0 && credential.Flags <= 255 && !credential.LastUsedAt.Valid && !credential.RevokedAt.Valid
}

func validWebAuthnCeremony(c WebAuthnCeremony) bool {
	if c.ID == "" || len(c.ID) > 128 || c.Kind != "registration" && c.Kind != "authentication" || c.Audience != "self-service" && c.Audience != "admin" {
		return false
	}
	if len(c.SessionData) < 1 || len(c.SessionData) > 65536 || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.CreatedAt) || c.ExpiresAt.After(c.CreatedAt.Add(5*time.Minute)) {
		return false
	}
	return c.Kind != "registration" || c.UserID.Valid
}

func (s *Store) EnsureWebAuthnUserHandle(ctx context.Context, userID int64) ([]byte, error) {
	if userID < 1 {
		return nil, errors.New("invalid WebAuthn user")
	}
	candidate := make([]byte, webAuthnHandleBytes)
	if _, err := rand.Read(candidate); err != nil {
		return nil, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO webauthn_users(user_id,user_handle) VALUES(?,?)`, userID, candidate); err != nil {
		return nil, err
	}
	var handle []byte
	if err = tx.QueryRowContext(ctx, `SELECT user_handle FROM webauthn_users WHERE user_id=?`, userID).Scan(&handle); err != nil {
		return nil, err
	}
	return append([]byte(nil), handle...), tx.Commit()
}

func (s *Store) CreateWebAuthnCeremony(ctx context.Context, ceremony WebAuthnCeremony) error {
	if ceremony.CreatedAt.IsZero() {
		ceremony.CreatedAt = time.Now().UTC()
	}
	if !validWebAuthnCeremony(ceremony) {
		return errors.New("invalid WebAuthn ceremony")
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO webauthn_ceremonies(id,kind,audience,user_id,session_data,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, ceremony.ID, ceremony.Kind, ceremony.Audience, nullableInt64(ceremony.UserID), ceremony.SessionData, ceremony.CreatedAt.UTC(), ceremony.ExpiresAt.UTC())
	return err
}

func nullableInt64(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func scanSQLiteWebAuthnCeremony(row *sql.Row) (WebAuthnCeremony, error) {
	var ceremony WebAuthnCeremony
	err := row.Scan(&ceremony.ID, &ceremony.Kind, &ceremony.Audience, &ceremony.UserID, &ceremony.SessionData, &ceremony.CreatedAt, &ceremony.ExpiresAt, &ceremony.ConsumedAt)
	return ceremony, err
}

func (s *Store) ActiveWebAuthnCeremony(ctx context.Context, id, kind, audience string, now time.Time) (WebAuthnCeremony, error) {
	if id == "" || len(id) > 128 || kind != "registration" && kind != "authentication" || audience != "self-service" && audience != "admin" || now.IsZero() {
		return WebAuthnCeremony{}, sql.ErrNoRows
	}
	return scanSQLiteWebAuthnCeremony(s.DB.QueryRowContext(ctx, `SELECT id,kind,audience,user_id,session_data,created_at,expires_at,consumed_at FROM webauthn_ceremonies WHERE id=? AND kind=? AND audience=? AND consumed_at IS NULL AND expires_at>=?`, id, kind, audience, now.UTC()))
}

func (s *Store) ConsumeWebAuthnCeremony(ctx context.Context, id, kind, audience string, now time.Time) (WebAuthnCeremony, error) {
	if id == "" || len(id) > 128 || kind != "registration" && kind != "authentication" || audience != "self-service" && audience != "admin" || now.IsZero() {
		return WebAuthnCeremony{}, sql.ErrNoRows
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return WebAuthnCeremony{}, err
	}
	defer tx.Rollback()
	ceremony, err := scanSQLiteWebAuthnCeremony(tx.QueryRowContext(ctx, `SELECT id,kind,audience,user_id,session_data,created_at,expires_at,consumed_at FROM webauthn_ceremonies WHERE id=? AND kind=? AND audience=? AND consumed_at IS NULL AND expires_at>=?`, id, kind, audience, now.UTC()))
	if err != nil {
		return WebAuthnCeremony{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE webauthn_ceremonies SET consumed_at=? WHERE id=? AND consumed_at IS NULL`, now.UTC(), id)
	if err != nil {
		return WebAuthnCeremony{}, err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return WebAuthnCeremony{}, sql.ErrNoRows
	}
	ceremony.ConsumedAt = sql.NullTime{Time: now.UTC(), Valid: true}
	if err := tx.Commit(); err != nil {
		return WebAuthnCeremony{}, err
	}
	return ceremony, nil
}

func (s *Store) WebAuthnUserByHandle(ctx context.Context, handle []byte) (u User, err error) {
	if len(handle) < 32 || len(handle) > 64 {
		return User{}, sql.ErrNoRows
	}
	err = s.DB.QueryRowContext(ctx, `SELECT u.id,u.username,u.display_name,u.directory_dn,u.pin_hash,u.pin_hash!='',u.oidc_subject,u.created_at FROM webauthn_users w JOIN users u ON u.id=w.user_id WHERE w.user_handle=?`, handle).Scan(&u.ID, &u.Username, &u.DisplayName, &u.DirectoryDN, &u.PINHash, &u.PINEnabled, &u.OIDCSubject, &u.CreatedAt)
	return u, err
}

func scanSQLiteWebAuthnCredential(rows *sql.Rows) (WebAuthnCredential, error) {
	var credential WebAuthnCredential
	err := rows.Scan(&credential.CredentialID, &credential.ManagementID, &credential.UserID, &credential.PublicKey, &credential.RPID, &credential.Name, &credential.Transports, &credential.AttestationType, &credential.AttestationFormat, &credential.Flags, &credential.SignCount, &credential.BackupEligible, &credential.BackupState, &credential.CreatedAt, &credential.LastUsedAt, &credential.RevokedAt)
	credential.CredentialID = append([]byte(nil), credential.CredentialID...)
	credential.PublicKey = append([]byte(nil), credential.PublicKey...)
	return credential, err
}

func (s *Store) WebAuthnCredentialsByUser(ctx context.Context, userID int64) ([]WebAuthnCredential, error) {
	if userID < 1 {
		return nil, errors.New("invalid WebAuthn user")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT credential_id,management_id,user_id,public_key,rp_id,name,transports,attestation_type,attestation_format,flags,sign_count,backup_eligible,backup_state,created_at,last_used_at,revoked_at FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at,credential_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	credentials := []WebAuthnCredential{}
	for rows.Next() {
		credential, err := scanSQLiteWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (s *Store) CompleteWebAuthnRegistration(ctx context.Context, ceremonyID, audience string, now time.Time, credential WebAuthnCredential, username, ip string) error {
	if credential.ManagementID == "" {
		var err error
		credential.ManagementID, err = newWebAuthnManagementID()
		if err != nil {
			return err
		}
	}
	if ceremonyID == "" || len(ceremonyID) > 128 || audience != "self-service" && audience != "admin" || now.IsZero() || !validWebAuthnCredential(credential) {
		return errors.New("invalid WebAuthn registration")
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	credential.CreatedAt = now.UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var userID int64
	var storedUsername string
	if err = tx.QueryRowContext(ctx, `SELECT c.user_id,u.username FROM webauthn_ceremonies c JOIN users u ON u.id=c.user_id WHERE c.id=? AND c.kind='registration' AND c.audience=? AND c.consumed_at IS NULL AND c.expires_at>=?`, ceremonyID, audience, now.UTC()).Scan(&userID, &storedUsername); err != nil {
		return err
	}
	if userID != credential.UserID || storedUsername != username {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO webauthn_credentials(credential_id,management_id,user_id,public_key,rp_id,name,transports,attestation_type,attestation_format,flags,sign_count,backup_eligible,backup_state,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, credential.CredentialID, credential.ManagementID, credential.UserID, credential.PublicKey, credential.RPID, credential.Name, credential.Transports, credential.AttestationType, credential.AttestationFormat, credential.Flags, credential.SignCount, credential.BackupEligible, credential.BackupState, credential.CreatedAt.UTC()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES(?,?,?,?)`, "passkey_registered", username, true, ip); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE webauthn_ceremonies SET consumed_at=? WHERE id=? AND consumed_at IS NULL`, now.UTC(), ceremonyID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func (s *Store) RevokeWebAuthnCredentialWithAudit(ctx context.Context, managementID string, userID int64, username, ip string, now time.Time) error {
	if len(managementID) < 16 || len(managementID) > 128 || userID < 1 || username == "" || len(username) > 256 || now.IsZero() {
		return errors.New("invalid WebAuthn revocation")
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var storedUsername string
	if err = tx.QueryRowContext(ctx, `SELECT u.username FROM webauthn_credentials c JOIN users u ON u.id=c.user_id WHERE c.management_id=? AND c.user_id=? AND c.revoked_at IS NULL`, managementID, userID).Scan(&storedUsername); err != nil {
		return err
	}
	if storedUsername != username {
		return sql.ErrNoRows
	}
	result, err := tx.ExecContext(ctx, `UPDATE webauthn_credentials SET revoked_at=? WHERE management_id=? AND user_id=? AND revoked_at IS NULL`, now.UTC(), managementID, userID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES(?,?,?,?)`, "passkey_revoked", username, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}

func validWebAuthnAuthentication(ceremonyID string, now time.Time, update WebAuthnAuthenticationUpdate, session SelfServiceSession) bool {
	return ceremonyID != "" && len(ceremonyID) <= 128 && !now.IsZero() &&
		len(update.CredentialID) >= 1 && len(update.CredentialID) <= 4096 && update.UserID > 0 &&
		session.ID != "" && len(session.ID) <= 128 && session.Username != "" && len(session.Username) <= 256 &&
		session.ExpiresAt.After(now) && !session.ExpiresAt.After(now.Add(15*time.Minute))
}

func validWebAuthnSignCount(previous, next uint32) bool {
	return previous == 0 && next == 0 || next > previous
}

func (s *Store) CompleteWebAuthnAuthentication(ctx context.Context, ceremonyID string, now time.Time, update WebAuthnAuthenticationUpdate, session SelfServiceSession, ip string) error {
	if !validWebAuthnAuthentication(ceremonyID, now, update, session) {
		return errors.New("invalid WebAuthn authentication")
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ceremonyUserID sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT user_id FROM webauthn_ceremonies WHERE id=? AND kind='authentication' AND audience='self-service' AND consumed_at IS NULL AND expires_at>=?`, ceremonyID, now.UTC()).Scan(&ceremonyUserID); err != nil {
		return err
	}
	var credentialUserID int64
	var username string
	var previousSignCount uint32
	if err = tx.QueryRowContext(ctx, `SELECT c.user_id,u.username,c.sign_count FROM webauthn_credentials c JOIN users u ON u.id=c.user_id WHERE c.credential_id=? AND c.revoked_at IS NULL`, update.CredentialID).Scan(&credentialUserID, &username, &previousSignCount); err != nil {
		return err
	}
	if credentialUserID != update.UserID || ceremonyUserID.Valid && ceremonyUserID.Int64 != update.UserID || username != session.Username || !validWebAuthnSignCount(previousSignCount, update.SignCount) {
		return sql.ErrNoRows
	}
	result, err := tx.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count=?,backup_state=?,last_used_at=? WHERE credential_id=? AND user_id=? AND revoked_at IS NULL AND sign_count=?`, update.SignCount, update.BackupState, now.UTC(), update.CredentialID, update.UserID, previousSignCount)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO self_service_sessions(id,username,created_at,expires_at) VALUES(?,?,?,?)`, session.ID, username, now.UTC(), session.ExpiresAt.UTC()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES(?,?,?,?)`, "passkey_login", username, true, ip); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE webauthn_ceremonies SET consumed_at=? WHERE id=? AND consumed_at IS NULL`, now.UTC(), ceremonyID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}
