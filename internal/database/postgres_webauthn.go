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
