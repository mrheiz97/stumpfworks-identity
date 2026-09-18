package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/TheRealHZL/stumpfworks-framework/data/migrate"
	frameworkpg "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	"github.com/jackc/pgx/v5"
)

// PostgresStore is a staged adapter, not yet wired into the Identity server.
// The caller owns the framework pool and performs migrations separately with
// migration credentials. Runtime constructors never execute DDL.
type PostgresStore struct{ pool *frameworkpg.Pool }

func NewPostgresStore(pool *frameworkpg.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, errors.New("Identity PostgreSQL pool required")
	}
	return &PostgresStore{pool: pool}, nil
}

func MigratePostgres(ctx context.Context, pool *frameworkpg.Pool) error {
	if pool == nil {
		return errors.New("Identity PostgreSQL pool required")
	}
	sum := sha256.Sum256([]byte(postgresSchema))
	return migrate.Apply(ctx, pool.Native(), []migrate.Migration{{Version: 1, Name: "001_identity.up.sql", SQL: postgresSchema, Checksum: hex.EncodeToString(sum[:])}})
}

func postgresNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return sql.ErrNoRows
	}
	return err
}

const postgresUserColumns = "id,username,display_name,directory_dn,pin_hash,pin_hash<>'',oidc_subject,created_at"

// SQLite's built-in lower() folds ASCII only. Preserve that behavior instead
// of inheriting PostgreSQL locale-dependent Unicode authentication semantics.
const postgresFoldUsername = "translate(username,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')"
const postgresFoldArgument = "translate($1::text,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')"

var ErrAmbiguousUser = errors.New("Identity username lookup ambiguous")

func scanPostgresUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.DirectoryDN, &u.PINHash, &u.PINEnabled, &u.OIDCSubject, &u.CreatedAt)
	return u, postgresNotFound(err)
}

func (s *PostgresStore) CreateUser(ctx context.Context, username, display, dn string) (User, error) {
	return scanPostgresUser(s.pool.Native().QueryRow(ctx, "INSERT INTO users(username,display_name,directory_dn) VALUES($1,$2,$3) RETURNING "+postgresUserColumns, username, display, dn))
}

func (s *PostgresStore) GetUser(ctx context.Context, id int64) (User, error) {
	return scanPostgresUser(s.pool.Native().QueryRow(ctx, "SELECT "+postgresUserColumns+" FROM users WHERE id=$1", id))
}

func (s *PostgresStore) UserByUsername(ctx context.Context, username string) (User, error) {
	rows, err := s.pool.Native().Query(ctx, "SELECT "+postgresUserColumns+" FROM users WHERE "+postgresFoldUsername+"="+postgresFoldArgument+" LIMIT 2", username)
	if err != nil {
		return User{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return User{}, err
		}
		return User{}, sql.ErrNoRows
	}
	user, err := scanPostgresUser(rows)
	if err != nil {
		return User{}, err
	}
	if rows.Next() {
		return User{}, ErrAmbiguousUser
	}
	return user, rows.Err()
}

// EnsureOIDCSubject locks the user row: concurrent callers receive the same
// persistent subject, and existing imported subjects are never regenerated.
func (s *PostgresStore) EnsureOIDCSubject(ctx context.Context, userID int64) (string, error) {
	var subject string
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT oidc_subject FROM users WHERE id=$1 FOR UPDATE", userID).Scan(&subject); err != nil {
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
		_, err := tx.Exec(ctx, "UPDATE users SET oidc_subject=$1,updated_at=now() WHERE id=$2", subject, userID)
		return err
	})
	return subject, err
}

func (s *PostgresStore) CreateOIDCClient(ctx context.Context, clientID, secretHash, redirectURIs, scopes string) error {
	_, err := s.pool.Native().Exec(ctx, "INSERT INTO oidc_clients(client_id,secret_hash,redirect_uris,scopes) VALUES($1,$2,$3,$4)", clientID, secretHash, redirectURIs, scopes)
	return err
}

func (s *PostgresStore) OIDCClientByID(ctx context.Context, clientID string) (OIDCClient, error) {
	var c OIDCClient
	err := s.pool.Native().QueryRow(ctx, "SELECT client_id,secret_hash,redirect_uris,scopes,enabled FROM oidc_clients WHERE client_id=$1", clientID).Scan(&c.ClientID, &c.SecretHash, &c.RedirectURIs, &c.Scopes, &c.Enabled)
	return c, postgresNotFound(err)
}

func (s *PostgresStore) CreateOIDCCode(ctx context.Context, c OIDCCode) error {
	if _, err := s.pool.Native().Exec(ctx, `DELETE FROM oidc_codes WHERE code_hash IN (SELECT code_hash FROM oidc_codes WHERE expires_at<now() LIMIT 100)`); err != nil {
		return err
	}
	_, err := s.pool.Native().Exec(ctx, "INSERT INTO oidc_codes(code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", c.CodeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scope, c.Nonce, c.CodeChallenge, c.ExpiresAt.UTC())
	return err
}

// ConsumeOIDCCode is one atomic statement; competing callbacks cannot both win.
func (s *PostgresStore) ConsumeOIDCCode(ctx context.Context, hash, clientID, redirectURI string, now time.Time) (OIDCCode, error) {
	var c OIDCCode
	err := s.pool.Native().QueryRow(ctx, `UPDATE oidc_codes SET consumed_at=$1 WHERE code_hash=$2 AND client_id=$3 AND redirect_uri=$4 AND consumed_at IS NULL AND expires_at>=$1 RETURNING code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at`, now.UTC(), hash, clientID, redirectURI).Scan(&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.Nonce, &c.CodeChallenge, &c.ExpiresAt)
	return c, postgresNotFound(err)
}
