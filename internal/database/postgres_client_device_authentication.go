package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) CreateClientEnrollmentTokenWithAudit(ctx context.Context, token ClientEnrollmentToken, ip string) error {
	if validateEnrollmentToken(token) != nil || validateAuditIP(ip) != nil {
		return ErrInvalidClientDeviceCredential
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `INSERT INTO client_enrollment_tokens(id,client_id,token_hash,created_at,expires_at) SELECT $1,client_id,$2,$3,$4 FROM clients WHERE client_id=$5 AND enabled=TRUE`, token.ID, token.TokenHash, token.CreatedAt.UTC(), token.ExpiresAt.UTC(), token.ClientID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5)`, "client_enrollment_created", token.ClientID, true, ip, "enrollment_id="+token.ID)
		return err
	})
}

func (s *PostgresStore) EnrollClientDeviceCredentialWithAudit(ctx context.Context, tokenHash string, now time.Time, credential ClientDeviceCredential, ip string) error {
	if !validSHA256(tokenHash) || validateDeviceCredential(credential) != nil || validateAuditIP(ip) != nil || now.IsZero() {
		return ErrInvalidClientDeviceCredential
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `UPDATE client_enrollment_tokens SET consumed_at=$1 WHERE token_hash=$2 AND client_id=$3 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>=$1 AND EXISTS(SELECT 1 FROM clients WHERE client_id=$3 AND enabled=TRUE)`, now.UTC(), tokenHash, credential.ClientID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		if _, err = tx.Exec(ctx, `INSERT INTO client_device_credentials(id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active')`, credential.ID, credential.ClientID, credential.FingerprintSHA256, credential.Serial, credential.URISAN, credential.PublicKeyAlgorithm, credential.IssuerID, credential.IssuedAt.UTC(), credential.ExpiresAt.UTC()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5)`, "client_device_enrolled", credential.ClientID, true, ip, "credential_id="+credential.ID)
		return err
	})
}

func (s *PostgresStore) RenewClientDeviceCredentialWithAudit(ctx context.Context, currentCredentialID string, now time.Time, replacement ClientDeviceCredential, ip string) error {
	if !validPublicIdentifier(currentCredentialID) || validateDeviceCredential(replacement) != nil || validateAuditIP(ip) != nil || now.IsZero() {
		return ErrInvalidClientDeviceCredential
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `UPDATE client_device_credentials SET status='superseded',updated_at=$1 WHERE id=$2 AND client_id=$3 AND status='active' AND expires_at>$1`, now.UTC(), currentCredentialID, replacement.ClientID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		if _, err = tx.Exec(ctx, `INSERT INTO client_device_credentials(id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active')`, replacement.ID, replacement.ClientID, replacement.FingerprintSHA256, replacement.Serial, replacement.URISAN, replacement.PublicKeyAlgorithm, replacement.IssuerID, replacement.IssuedAt.UTC(), replacement.ExpiresAt.UTC()); err != nil {
			return err
		}
		details := "credential_id=" + replacement.ID + ",supersedes=" + currentCredentialID
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5)`, "client_device_renewed", replacement.ClientID, true, ip, details)
		return err
	})
}

func (s *PostgresStore) ClientDeviceCredentials(ctx context.Context, clientID string) ([]ClientDeviceCredential, error) {
	rows, err := s.pool.Native().Query(ctx, `SELECT id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status,revoked_at,created_at,updated_at FROM client_device_credentials WHERE client_id=$1 ORDER BY created_at,id`, clientID)
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

func (s *PostgresStore) ActiveClientDeviceCredential(ctx context.Context, clientID string, now time.Time) (credential ClientDeviceCredential, err error) {
	if !validPublicIdentifier(clientID) || now.IsZero() {
		return credential, ErrInvalidClientDeviceCredential
	}
	err = s.pool.Native().QueryRow(ctx, `SELECT id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status,revoked_at,created_at,updated_at FROM client_device_credentials WHERE client_id=$1 AND status='active' AND issued_at<=$2 AND expires_at>$2`, clientID, now.UTC()).Scan(&credential.ID, &credential.ClientID, &credential.FingerprintSHA256, &credential.Serial, &credential.URISAN, &credential.PublicKeyAlgorithm, &credential.IssuerID, &credential.IssuedAt, &credential.ExpiresAt, &credential.Status, &credential.RevokedAt, &credential.CreatedAt, &credential.UpdatedAt)
	return credential, err
}

func (s *PostgresStore) RevokeClientDeviceCredentialWithAudit(ctx context.Context, clientID, credentialID, ip string, now time.Time) error {
	if !validPublicIdentifier(clientID) || !validPublicIdentifier(credentialID) || validateAuditIP(ip) != nil || now.IsZero() {
		return ErrInvalidClientDeviceCredential
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `UPDATE client_device_credentials SET status='revoked',revoked_at=$1,updated_at=$1 WHERE id=$2 AND client_id=$3 AND status='active'`, now.UTC(), credentialID, clientID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5)`, "client_device_revoked", clientID, true, ip, "credential_id="+credentialID)
		return err
	})
}

func (s *PostgresStore) SetClientAuthenticationModeWithAudit(ctx context.Context, clientID, mode, ip string, now time.Time) error {
	if !validPublicIdentifier(clientID) || !validClientAuthMode(mode) || validateAuditIP(ip) != nil || now.IsZero() {
		return ErrInvalidClientDeviceCredential
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		query := `UPDATE clients SET auth_mode=$1,updated_at=$2 WHERE client_id=$3`
		args := []any{mode, now.UTC(), clientID}
		if mode != ClientAuthTokenOnly {
			query += ` AND EXISTS(SELECT 1 FROM client_device_credentials WHERE client_id=$3 AND status='active' AND expires_at>$2)`
		}
		result, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5)`, "client_authentication_mode_changed", clientID, true, ip, "mode="+mode)
		return err
	})
}
