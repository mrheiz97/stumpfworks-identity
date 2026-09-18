package database

import (
	"context"
	"database/sql"
	"time"
)

func (s *PostgresStore) Users(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Native().Query(ctx, "SELECT "+postgresUserColumns+" FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanPostgresUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetUserPIN(ctx context.Context, id int64, hash string) error {
	result, err := s.pool.Native().Exec(ctx, "UPDATE users SET pin_hash=$1,updated_at=now() WHERE id=$2", hash, id)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) UpsertOIDCClient(ctx context.Context, clientID, secretHash, redirectURIs, scopes string) error {
	_, err := s.pool.Native().Exec(ctx, `INSERT INTO oidc_clients(client_id,secret_hash,redirect_uris,scopes) VALUES($1,$2,$3,$4) ON CONFLICT(client_id) DO UPDATE SET secret_hash=excluded.secret_hash,redirect_uris=excluded.redirect_uris,scopes=excluded.scopes,enabled=TRUE,updated_at=now()`, clientID, secretHash, redirectURIs, scopes)
	return err
}

func (s *PostgresStore) RotateOIDCClientSecret(ctx context.Context, clientID, secretHash string) error {
	result, err := s.pool.Native().Exec(ctx, "UPDATE oidc_clients SET secret_hash=$1,updated_at=now() WHERE client_id=$2", secretHash, clientID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) SetOIDCClientEnabled(ctx context.Context, clientID string, enabled bool) error {
	result, err := s.pool.Native().Exec(ctx, "UPDATE oidc_clients SET enabled=$1,updated_at=now() WHERE client_id=$2", enabled, clientID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) CreateSelfServiceSession(ctx context.Context, id, username string, expiresAt time.Time) error {
	_, err := s.pool.Native().Exec(ctx, "INSERT INTO self_service_sessions(id,username,expires_at) VALUES($1,$2,$3)", id, username, expiresAt.UTC())
	return err
}

func (s *PostgresStore) ActiveSelfServiceSession(ctx context.Context, id, username string, now time.Time) (SelfServiceSession, error) {
	var session SelfServiceSession
	err := s.pool.Native().QueryRow(ctx, "SELECT id,username,created_at,expires_at FROM self_service_sessions WHERE id=$2 AND "+postgresFoldUsername+"="+postgresFoldArgument+" AND revoked_at IS NULL AND expires_at>=$3", username, id, now.UTC()).Scan(&session.ID, &session.Username, &session.CreatedAt, &session.ExpiresAt)
	return session, postgresNotFound(err)
}

func (s *PostgresStore) ActiveSelfServiceSessions(ctx context.Context, username string, now time.Time) ([]SelfServiceSession, error) {
	rows, err := s.pool.Native().Query(ctx, "SELECT id,username,created_at,expires_at FROM self_service_sessions WHERE "+postgresFoldUsername+"="+postgresFoldArgument+" AND revoked_at IS NULL AND expires_at>=$2 ORDER BY created_at DESC LIMIT 20", username, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SelfServiceSession{}
	for rows.Next() {
		var session SelfServiceSession
		if err := rows.Scan(&session.ID, &session.Username, &session.CreatedAt, &session.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, session)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeOtherSelfServiceSessions(ctx context.Context, username, currentID string) (int64, error) {
	result, err := s.pool.Native().Exec(ctx, "UPDATE self_service_sessions SET revoked_at=now() WHERE "+postgresFoldUsername+"="+postgresFoldArgument+" AND id<>$2 AND revoked_at IS NULL AND expires_at>=now()", username, currentID)
	return result.RowsAffected(), err
}

func (s *PostgresStore) RevokeSelfServiceSession(ctx context.Context, id, username string) error {
	_, err := s.pool.Native().Exec(ctx, "UPDATE self_service_sessions SET revoked_at=now() WHERE id=$2 AND "+postgresFoldUsername+"="+postgresFoldArgument, username, id)
	return err
}
