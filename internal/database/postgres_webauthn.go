package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) EnsureWebAuthnUserHandle(ctx context.Context, userID int64) ([]byte, error) {
	if userID < 1 {
		return nil, errors.New("invalid WebAuthn user")
	}
	candidate := make([]byte, webAuthnHandleBytes)
	if _, err := rand.Read(candidate); err != nil {
		return nil, err
	}
	var handle []byte
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO webauthn_users(user_id,user_handle) VALUES($1,$2) ON CONFLICT(user_id) DO NOTHING`, userID, candidate); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT user_handle FROM webauthn_users WHERE user_id=$1 FOR UPDATE`, userID).Scan(&handle)
	})
	return append([]byte(nil), handle...), err
}

func (s *PostgresStore) CreateWebAuthnCeremony(ctx context.Context, ceremony WebAuthnCeremony) error {
	if ceremony.CreatedAt.IsZero() {
		ceremony.CreatedAt = time.Now().UTC()
	}
	if !validWebAuthnCeremony(ceremony) {
		return errors.New("invalid WebAuthn ceremony")
	}
	_, err := s.pool.Native().Exec(ctx, `INSERT INTO webauthn_ceremonies(id,kind,audience,user_id,session_data,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, ceremony.ID, ceremony.Kind, ceremony.Audience, nullableInt64(ceremony.UserID), ceremony.SessionData, ceremony.CreatedAt.UTC(), ceremony.ExpiresAt.UTC())
	return err
}

func scanPostgresWebAuthnCeremony(row pgx.Row) (WebAuthnCeremony, error) {
	var ceremony WebAuthnCeremony
	err := row.Scan(&ceremony.ID, &ceremony.Kind, &ceremony.Audience, &ceremony.UserID, &ceremony.SessionData, &ceremony.CreatedAt, &ceremony.ExpiresAt, &ceremony.ConsumedAt)
	return ceremony, postgresNotFound(err)
}

func (s *PostgresStore) ConsumeWebAuthnCeremony(ctx context.Context, id, kind, audience string, now time.Time) (ceremony WebAuthnCeremony, resultErr error) {
	if id == "" || len(id) > 128 || kind != "registration" && kind != "authentication" || audience != "self-service" && audience != "admin" || now.IsZero() {
		return WebAuthnCeremony{}, sql.ErrNoRows
	}
	resultErr = s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		ceremony, err = scanPostgresWebAuthnCeremony(tx.QueryRow(ctx, `SELECT id,kind,audience,user_id,session_data,created_at,expires_at,consumed_at FROM webauthn_ceremonies WHERE id=$1 AND kind=$2 AND audience=$3 AND consumed_at IS NULL AND expires_at>=$4 FOR UPDATE`, id, kind, audience, now.UTC()))
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `UPDATE webauthn_ceremonies SET consumed_at=$1 WHERE id=$2 AND consumed_at IS NULL`, now.UTC(), id)
		if err != nil || result.RowsAffected() != 1 {
			if err != nil {
				return err
			}
			return sql.ErrNoRows
		}
		ceremony.ConsumedAt = sql.NullTime{Time: now.UTC(), Valid: true}
		return nil
	})
	return ceremony, resultErr
}

func (s *PostgresStore) WebAuthnUserByHandle(ctx context.Context, handle []byte) (User, error) {
	if len(handle) < 32 || len(handle) > 64 {
		return User{}, sql.ErrNoRows
	}
	return scanPostgresUser(s.pool.Native().QueryRow(ctx, `SELECT u.id,u.username,u.display_name,u.directory_dn,u.pin_hash,u.pin_hash<>'',u.oidc_subject,u.created_at FROM webauthn_users w JOIN users u ON u.id=w.user_id WHERE w.user_handle=$1`, handle))
}

func scanPostgresWebAuthnCredential(row pgx.Row) (WebAuthnCredential, error) {
	var credential WebAuthnCredential
	err := row.Scan(&credential.CredentialID, &credential.UserID, &credential.PublicKey, &credential.RPID, &credential.Name, &credential.Transports, &credential.AttestationType, &credential.AttestationFormat, &credential.Flags, &credential.SignCount, &credential.BackupEligible, &credential.BackupState, &credential.CreatedAt, &credential.LastUsedAt, &credential.RevokedAt)
	credential.CredentialID = append([]byte(nil), credential.CredentialID...)
	credential.PublicKey = append([]byte(nil), credential.PublicKey...)
	return credential, postgresNotFound(err)
}

func (s *PostgresStore) WebAuthnCredentialsByUser(ctx context.Context, userID int64) ([]WebAuthnCredential, error) {
	if userID < 1 {
		return nil, errors.New("invalid WebAuthn user")
	}
	rows, err := s.pool.Native().Query(ctx, `SELECT credential_id,user_id,public_key,rp_id,name,transports,attestation_type,attestation_format,flags,sign_count,backup_eligible,backup_state,created_at,last_used_at,revoked_at FROM webauthn_credentials WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at,credential_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	credentials := []WebAuthnCredential{}
	for rows.Next() {
		credential, err := scanPostgresWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (s *PostgresStore) CompleteWebAuthnRegistration(ctx context.Context, ceremonyID, audience string, now time.Time, credential WebAuthnCredential, username, ip string) error {
	if ceremonyID == "" || len(ceremonyID) > 128 || audience != "self-service" && audience != "admin" || now.IsZero() || !validWebAuthnCredential(credential) {
		return errors.New("invalid WebAuthn registration")
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	credential.CreatedAt = now.UTC()
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var userID int64
		var storedUsername string
		if err := tx.QueryRow(ctx, `SELECT c.user_id,u.username FROM webauthn_ceremonies c JOIN users u ON u.id=c.user_id WHERE c.id=$1 AND c.kind='registration' AND c.audience=$2 AND c.consumed_at IS NULL AND c.expires_at>=$3 FOR UPDATE OF c`, ceremonyID, audience, now.UTC()).Scan(&userID, &storedUsername); err != nil {
			return postgresNotFound(err)
		}
		if userID != credential.UserID || storedUsername != username {
			return sql.ErrNoRows
		}
		if _, err := tx.Exec(ctx, `INSERT INTO webauthn_credentials(credential_id,user_id,public_key,rp_id,name,transports,attestation_type,attestation_format,flags,sign_count,backup_eligible,backup_state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, credential.CredentialID, credential.UserID, credential.PublicKey, credential.RPID, credential.Name, credential.Transports, credential.AttestationType, credential.AttestationFormat, credential.Flags, credential.SignCount, credential.BackupEligible, credential.BackupState, credential.CreatedAt.UTC()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES($1,$2,$3,$4)`, "passkey_registered", username, true, ip); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `UPDATE webauthn_ceremonies SET consumed_at=$1 WHERE id=$2 AND consumed_at IS NULL`, now.UTC(), ceremonyID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (s *PostgresStore) CompleteWebAuthnAuthentication(ctx context.Context, ceremonyID string, now time.Time, update WebAuthnAuthenticationUpdate, session SelfServiceSession, ip string) error {
	if !validWebAuthnAuthentication(ceremonyID, now, update, session) {
		return errors.New("invalid WebAuthn authentication")
	}
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var ceremonyUserID sql.NullInt64
		if err := tx.QueryRow(ctx, `SELECT user_id FROM webauthn_ceremonies WHERE id=$1 AND kind='authentication' AND audience='self-service' AND consumed_at IS NULL AND expires_at>=$2 FOR UPDATE`, ceremonyID, now.UTC()).Scan(&ceremonyUserID); err != nil {
			return postgresNotFound(err)
		}
		var credentialUserID int64
		var username string
		var previousSignCount uint32
		if err := tx.QueryRow(ctx, `SELECT c.user_id,u.username,c.sign_count FROM webauthn_credentials c JOIN users u ON u.id=c.user_id WHERE c.credential_id=$1 AND c.revoked_at IS NULL FOR UPDATE OF c`, update.CredentialID).Scan(&credentialUserID, &username, &previousSignCount); err != nil {
			return postgresNotFound(err)
		}
		if credentialUserID != update.UserID || ceremonyUserID.Valid && ceremonyUserID.Int64 != update.UserID || username != session.Username || !validWebAuthnSignCount(previousSignCount, update.SignCount) {
			return sql.ErrNoRows
		}
		result, err := tx.Exec(ctx, `UPDATE webauthn_credentials SET sign_count=$1,backup_state=$2,last_used_at=$3 WHERE credential_id=$4 AND user_id=$5 AND revoked_at IS NULL AND sign_count=$6`, update.SignCount, update.BackupState, now.UTC(), update.CredentialID, update.UserID, previousSignCount)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		if _, err = tx.Exec(ctx, `INSERT INTO self_service_sessions(id,username,created_at,expires_at) VALUES($1,$2,$3,$4)`, session.ID, username, now.UTC(), session.ExpiresAt.UTC()); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES($1,$2,$3,$4)`, "passkey_login", username, true, ip); err != nil {
			return err
		}
		result, err = tx.Exec(ctx, `UPDATE webauthn_ceremonies SET consumed_at=$1 WHERE id=$2 AND consumed_at IS NULL`, now.UTC(), ceremonyID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		return nil
	})
}
