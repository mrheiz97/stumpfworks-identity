package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"time"
)

const webAuthnHandleBytes = 32

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
