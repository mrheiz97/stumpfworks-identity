package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"time"
)

const migration = `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, directory_dn TEXT NOT NULL DEFAULT '', pin_hash TEXT NOT NULL DEFAULT '', oidc_subject TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS badges (id INTEGER PRIMARY KEY AUTOINCREMENT, badge_code TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id), token_hash TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT 1, description TEXT NOT NULL DEFAULT '', issued_by TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, last_used_at DATETIME, revoked_at DATETIME);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, badge_id TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '', client_id TEXT NOT NULL DEFAULT '', success BOOLEAN NOT NULL, ip_address TEXT NOT NULL DEFAULT '', timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, details TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT 1, version TEXT NOT NULL DEFAULT '', network_status TEXT NOT NULL DEFAULT 'unknown', ad_status TEXT NOT NULL DEFAULT 'unknown', camera_status TEXT NOT NULL DEFAULT 'unknown', kerberos_status TEXT NOT NULL DEFAULT 'unknown', last_update_version TEXT NOT NULL DEFAULT '', last_update_status TEXT NOT NULL DEFAULT 'unknown', last_update_at DATETIME, rollback_available BOOLEAN NOT NULL DEFAULT 0, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen_at DATETIME);
CREATE TABLE IF NOT EXISTS self_service_sessions (id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME NOT NULL, revoked_at DATETIME);
CREATE TABLE IF NOT EXISTS oidc_clients (client_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, redirect_uris TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT 'openid', enabled BOOLEAN NOT NULL DEFAULT 1, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS oidc_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oidc_clients(client_id), user_id INTEGER NOT NULL REFERENCES users(id), redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, nonce TEXT NOT NULL, code_challenge TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME NOT NULL, consumed_at DATETIME);
CREATE INDEX IF NOT EXISTS idx_badges_code ON badges(badge_code); CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp); CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen_at);`

type Store struct{ DB *sql.DB }
type User struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	DirectoryDN string    `json:"directory_dn"`
	PINHash     string    `json:"-"`
	PINEnabled  bool      `json:"pin_enabled"`
	OIDCSubject string    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}
type OIDCClient struct {
	ClientID, SecretHash, RedirectURIs, Scopes string
	Enabled                                    bool
}
type OIDCCode struct {
	CodeHash, ClientID, RedirectURI, Scope, Nonce, CodeChallenge string
	UserID                                                       int64
	ExpiresAt                                                    time.Time
}
type Badge struct {
	ID                int64        `json:"id"`
	BadgeCode         string       `json:"badge_code"`
	UserID            int64        `json:"user_id"`
	Username          string       `json:"username"`
	DisplayName       string       `json:"display_name"`
	PINHash           string       `json:"-"`
	TokenHash         string       `json:"-"`
	Enabled           bool         `json:"enabled"`
	ActivationPending bool         `json:"activation_pending"`
	Description       string       `json:"description"`
	CreatedAt         time.Time    `json:"created_at"`
	LastUsedAt        sql.NullTime `json:"-"`
	RevokedAt         sql.NullTime `json:"-"`
}
type UserBadge struct {
	ID          int64
	BadgeCode   string
	Description string
	CreatedAt   time.Time
	LastUsedAt  sql.NullTime
}
type UserAuthEvent struct {
	BadgeID   string
	ClientID  string
	Success   bool
	Timestamp time.Time
}
type SelfServiceSession struct {
	ID        string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}
type Audit struct {
	ID                                     int64 `json:"id"`
	EventType, BadgeID, Username, ClientID string
	Success                                bool
	IPAddress                              string
	Timestamp                              time.Time
	Details                                string
}
type Client struct {
	ID                int64      `json:"id"`
	ClientID          string     `json:"client_id"`
	TokenHash         string     `json:"-"`
	Version           string     `json:"version"`
	NetworkStatus     string     `json:"network_status"`
	ADStatus          string     `json:"ad_status"`
	CameraStatus      string     `json:"camera_status"`
	KerberosStatus    string     `json:"kerberos_status"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	LastUpdateVersion string     `json:"last_update_version"`
	LastUpdateStatus  string     `json:"last_update_status"`
	LastUpdateAt      *time.Time `json:"last_update_at,omitempty"`
	RollbackAvailable bool       `json:"rollback_available"`
	Enabled           bool       `json:"enabled"`
}

type ClientUpdate struct {
	Version           string
	Status            string
	UpdatedAt         time.Time
	RollbackAvailable bool
}

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(migration); err != nil {
		db.Close()
		return nil, err
	}
	var pinColumns int
	if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('users') WHERE name='pin_hash'`).Scan(&pinColumns); err != nil {
		db.Close()
		return nil, err
	}
	if pinColumns == 0 {
		if _, err = db.Exec(`ALTER TABLE users ADD COLUMN pin_hash TEXT NOT NULL DEFAULT ''`); err != nil {
			db.Close()
			return nil, err
		}
	}
	var activationColumns int
	if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('badges') WHERE name='activation_pending'`).Scan(&activationColumns); err != nil {
		db.Close()
		return nil, err
	}
	if activationColumns == 0 {
		if _, err = db.Exec(`ALTER TABLE badges ADD COLUMN activation_pending BOOLEAN NOT NULL DEFAULT 0`); err != nil {
			db.Close()
			return nil, err
		}
	}
	var subjectColumns int
	if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('users') WHERE name='oidc_subject'`).Scan(&subjectColumns); err != nil {
		db.Close()
		return nil, err
	}
	if subjectColumns == 0 {
		if _, err = db.Exec(`ALTER TABLE users ADD COLUMN oidc_subject TEXT NOT NULL DEFAULT ''`); err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_subject ON users(oidc_subject) WHERE oidc_subject<>''; CREATE INDEX IF NOT EXISTS idx_oidc_codes_expiry ON oidc_codes(expires_at)`); err != nil {
		db.Close()
		return nil, err
	}
	for _, column := range []struct{ name, definition string }{{"enabled", "BOOLEAN NOT NULL DEFAULT 1"}, {"updated_at", "DATETIME"}, {"last_update_version", "TEXT NOT NULL DEFAULT ''"}, {"last_update_status", "TEXT NOT NULL DEFAULT 'unknown'"}, {"last_update_at", "DATETIME"}, {"rollback_available", "BOOLEAN NOT NULL DEFAULT 0"}} {
		var count int
		if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('clients') WHERE name=?`, column.name).Scan(&count); err != nil {
			db.Close()
			return nil, err
		}
		if count == 0 {
			if _, err = db.Exec(`ALTER TABLE clients ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) CreateUser(ctx context.Context, u, d, dn string) (User, error) {
	r, err := s.DB.ExecContext(ctx, `INSERT INTO users(username,display_name,directory_dn) VALUES(?,?,?)`, u, d, dn)
	if err != nil {
		return User{}, err
	}
	id, _ := r.LastInsertId()
	return s.GetUser(ctx, id)
}
func (s *Store) GetUser(ctx context.Context, id int64) (u User, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT id,username,display_name,directory_dn,pin_hash,pin_hash!='',oidc_subject,created_at FROM users WHERE id=?`, id).Scan(&u.ID, &u.Username, &u.DisplayName, &u.DirectoryDN, &u.PINHash, &u.PINEnabled, &u.OIDCSubject, &u.CreatedAt)
	return
}
func (s *Store) UserByUsername(ctx context.Context, username string) (u User, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT id,username,display_name,directory_dn,pin_hash,pin_hash!='',oidc_subject,created_at FROM users WHERE lower(username)=lower(?)`, username).Scan(&u.ID, &u.Username, &u.DisplayName, &u.DirectoryDN, &u.PINHash, &u.PINEnabled, &u.OIDCSubject, &u.CreatedAt)
	return
}
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT id,username,display_name,directory_dn,pin_hash,pin_hash!='',oidc_subject,created_at FROM users ORDER BY username`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if e = rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.DirectoryDN, &u.PINHash, &u.PINEnabled, &u.OIDCSubject, &u.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s *Store) SetUserPIN(ctx context.Context, id int64, hash string) error {
	r, e := s.DB.ExecContext(ctx, `UPDATE users SET pin_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, hash, id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) nextCode(ctx context.Context, tx *sql.Tx) (string, error) {
	var n int64
	if e := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0)+1 FROM badges`).Scan(&n); e != nil {
		return "", e
	}
	return fmt.Sprintf("SW-%04d", n), nil
}
func (s *Store) CreateBadge(ctx context.Context, user int64, hash, desc string) (Badge, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Badge{}, e
	}
	defer tx.Rollback()
	code, e := s.nextCode(ctx, tx)
	if e != nil {
		return Badge{}, e
	}
	r, e := tx.ExecContext(ctx, `INSERT INTO badges(badge_code,user_id,token_hash,description) VALUES(?,?,?,?)`, code, user, hash, desc)
	if e != nil {
		return Badge{}, e
	}
	id, _ := r.LastInsertId()
	if e = tx.Commit(); e != nil {
		return Badge{}, e
	}
	return s.GetBadge(ctx, id)
}
func (s *Store) ReplaceBadgePending(ctx context.Context, oldID int64, tokenHash, description string) (Badge, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Badge{}, err
	}
	defer tx.Rollback()
	var userID int64
	if err = tx.QueryRowContext(ctx, `SELECT user_id FROM badges WHERE id=? AND enabled=1`, oldID).Scan(&userID); err != nil {
		return Badge{}, err
	}
	code, err := s.nextCode(ctx, tx)
	if err != nil {
		return Badge{}, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE badges SET enabled=0,activation_pending=0,revoked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND enabled=1`, oldID)
	if err != nil {
		return Badge{}, err
	}
	if changed, changeErr := updated.RowsAffected(); changeErr != nil || changed != 1 {
		return Badge{}, sql.ErrNoRows
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO badges(badge_code,user_id,token_hash,enabled,activation_pending,description) VALUES(?,?,?,0,1,?)`, code, userID, tokenHash, description)
	if err != nil {
		return Badge{}, err
	}
	id, _ := result.LastInsertId()
	if err = tx.Commit(); err != nil {
		return Badge{}, err
	}
	return s.GetBadge(ctx, id)
}
func (s *Store) GetBadge(ctx context.Context, id int64) (b Badge, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT b.id,b.badge_code,b.user_id,u.username,u.display_name,u.pin_hash,b.token_hash,b.enabled,b.activation_pending,b.description,b.created_at,b.last_used_at,b.revoked_at FROM badges b JOIN users u ON u.id=b.user_id WHERE b.id=?`, id).Scan(&b.ID, &b.BadgeCode, &b.UserID, &b.Username, &b.DisplayName, &b.PINHash, &b.TokenHash, &b.Enabled, &b.ActivationPending, &b.Description, &b.CreatedAt, &b.LastUsedAt, &b.RevokedAt)
	return
}
func (s *Store) BadgeByCode(ctx context.Context, c string) (b Badge, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT b.id,b.badge_code,b.user_id,u.username,u.display_name,u.pin_hash,b.token_hash,b.enabled,b.activation_pending,b.description,b.created_at,b.last_used_at,b.revoked_at FROM badges b JOIN users u ON u.id=b.user_id WHERE b.badge_code=?`, c).Scan(&b.ID, &b.BadgeCode, &b.UserID, &b.Username, &b.DisplayName, &b.PINHash, &b.TokenHash, &b.Enabled, &b.ActivationPending, &b.Description, &b.CreatedAt, &b.LastUsedAt, &b.RevokedAt)
	return
}
func (s *Store) Badges(ctx context.Context) ([]Badge, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT b.id,b.badge_code,b.user_id,u.username,u.display_name,u.pin_hash,b.token_hash,b.enabled,b.activation_pending,b.description,b.created_at,b.last_used_at,b.revoked_at FROM badges b JOIN users u ON u.id=b.user_id ORDER BY b.id DESC`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Badge{}
	for rows.Next() {
		var b Badge
		if e = rows.Scan(&b.ID, &b.BadgeCode, &b.UserID, &b.Username, &b.DisplayName, &b.PINHash, &b.TokenHash, &b.Enabled, &b.ActivationPending, &b.Description, &b.CreatedAt, &b.LastUsedAt, &b.RevokedAt); e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (s *Store) ActiveBadgesByUser(ctx context.Context, userID int64) ([]UserBadge, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,badge_code,description,created_at,last_used_at FROM badges WHERE user_id=? AND enabled=1 ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserBadge{}
	for rows.Next() {
		var b UserBadge
		if err = rows.Scan(&b.ID, &b.BadgeCode, &b.Description, &b.CreatedAt, &b.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (s *Store) RevokeActiveBadgeForUser(ctx context.Context, badgeID, userID int64) (UserBadge, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return UserBadge{}, err
	}
	defer tx.Rollback()
	var b UserBadge
	err = tx.QueryRowContext(ctx, `SELECT id,badge_code,description,created_at,last_used_at FROM badges WHERE id=? AND user_id=? AND enabled=1`, badgeID, userID).Scan(&b.ID, &b.BadgeCode, &b.Description, &b.CreatedAt, &b.LastUsedAt)
	if err != nil {
		return UserBadge{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE badges SET enabled=0,revoked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=? AND enabled=1`, badgeID, userID)
	if err != nil {
		return UserBadge{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return UserBadge{}, sql.ErrNoRows
	}
	if err = tx.Commit(); err != nil {
		return UserBadge{}, err
	}
	return b, nil
}
func (s *Store) ActivatePendingBadgeForUser(ctx context.Context, badgeID, userID int64) error {
	result, err := s.DB.ExecContext(ctx, `UPDATE badges SET enabled=1,activation_pending=0,revoked_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=? AND enabled=0 AND activation_pending=1`, badgeID, userID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) Revoke(ctx context.Context, id int64) error {
	_, e := s.DB.ExecContext(ctx, `UPDATE badges SET enabled=0,activation_pending=0,revoked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	return e
}
func (s *Store) Used(ctx context.Context, id int64) error {
	_, e := s.DB.ExecContext(ctx, `UPDATE badges SET last_used_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	return e
}
func (s *Store) Audit(ctx context.Context, event, bid, user, client string, success bool, ip, details string) {
	_, _ = s.DB.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,client_id,success,ip_address,details) VALUES(?,?,?,?,?,?,?)`, event, bid, user, client, success, ip, details)
}
func (s *Store) Audits(ctx context.Context) ([]Audit, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT id,event_type,badge_id,username,client_id,success,ip_address,timestamp,details FROM audit_log ORDER BY id DESC LIMIT 200`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var a Audit
		if e = rows.Scan(&a.ID, &a.EventType, &a.BadgeID, &a.Username, &a.ClientID, &a.Success, &a.IPAddress, &a.Timestamp, &a.Details); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) RecentBadgeAuthByUser(ctx context.Context, username string) ([]UserAuthEvent, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT badge_id,client_id,success,timestamp FROM audit_log WHERE lower(username)=lower(?) AND event_type IN ('auth_success','auth_failed') ORDER BY id DESC LIMIT 20`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserAuthEvent{}
	for rows.Next() {
		var event UserAuthEvent
		if err = rows.Scan(&event.BadgeID, &event.ClientID, &event.Success, &event.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}
func (s *Store) CreateSelfServiceSession(ctx context.Context, id, username string, expiresAt time.Time) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO self_service_sessions(id,username,expires_at) VALUES(?,?,?)`, id, username, expiresAt.UTC())
	return err
}
func (s *Store) ActiveSelfServiceSession(ctx context.Context, id, username string, now time.Time) (SelfServiceSession, error) {
	var session SelfServiceSession
	err := s.DB.QueryRowContext(ctx, `SELECT id,username,created_at,expires_at FROM self_service_sessions WHERE id=? AND lower(username)=lower(?) AND revoked_at IS NULL AND expires_at>=?`, id, username, now.UTC()).Scan(&session.ID, &session.Username, &session.CreatedAt, &session.ExpiresAt)
	return session, err
}
func (s *Store) ActiveSelfServiceSessions(ctx context.Context, username string, now time.Time) ([]SelfServiceSession, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,username,created_at,expires_at FROM self_service_sessions WHERE lower(username)=lower(?) AND revoked_at IS NULL AND expires_at>=? ORDER BY created_at DESC LIMIT 20`, username, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SelfServiceSession{}
	for rows.Next() {
		var session SelfServiceSession
		if err = rows.Scan(&session.ID, &session.Username, &session.CreatedAt, &session.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, session)
	}
	return out, rows.Err()
}
func (s *Store) RevokeOtherSelfServiceSessions(ctx context.Context, username, currentID string) (int64, error) {
	result, err := s.DB.ExecContext(ctx, `UPDATE self_service_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE lower(username)=lower(?) AND id<>? AND revoked_at IS NULL AND expires_at>=CURRENT_TIMESTAMP`, username, currentID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
func (s *Store) RevokeSelfServiceSession(ctx context.Context, id, username string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE self_service_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND lower(username)=lower(?)`, id, username)
	return err
}
// Counts is the error-returning runtime contract shared with PostgreSQL.
func (s *Store) Counts(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for k, q := range map[string]string{"users": "SELECT count(*) FROM users", "badges": "SELECT count(*) FROM badges", "active": "SELECT count(*) FROM badges WHERE enabled=1", "revoked": "SELECT count(*) FROM badges WHERE enabled=0", "today": "SELECT count(*) FROM audit_log WHERE event_type='auth_success' AND date(timestamp)=date('now')", "failed": "SELECT count(*) FROM audit_log WHERE event_type='auth_failed' AND date(timestamp)=date('now')"} {
		var n int64
		if err := s.DB.QueryRowContext(ctx, q).Scan(&n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, nil
}

func (s *Store) CreateClient(ctx context.Context, clientID, tokenHash string) (Client, error) {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO clients(client_id,token_hash) VALUES(?,?)`, clientID, tokenHash)
	if err != nil {
		return Client{}, err
	}
	return s.ClientByID(ctx, clientID)
}

func (s *Store) ClientByID(ctx context.Context, clientID string) (c Client, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT id,client_id,token_hash,enabled,version,network_status,ad_status,camera_status,kerberos_status,last_update_version,last_update_status,last_update_at,rollback_available,created_at,last_seen_at FROM clients WHERE client_id=?`, clientID).Scan(&c.ID, &c.ClientID, &c.TokenHash, &c.Enabled, &c.Version, &c.NetworkStatus, &c.ADStatus, &c.CameraStatus, &c.KerberosStatus, &c.LastUpdateVersion, &c.LastUpdateStatus, &c.LastUpdateAt, &c.RollbackAvailable, &c.CreatedAt, &c.LastSeenAt)
	return
}

func (s *Store) UpdateClientStatus(ctx context.Context, clientID, version, network, ad, camera, kerberos string) error {
	return s.UpdateClientStatusWithUpdate(ctx, clientID, version, network, ad, camera, kerberos, nil)
}

func (s *Store) UpdateClientStatusWithUpdate(ctx context.Context, clientID, version, network, ad, camera, kerberos string, update *ClientUpdate) error {
	if update != nil {
		r, err := s.DB.ExecContext(ctx, `UPDATE clients SET version=?,network_status=?,ad_status=?,camera_status=?,kerberos_status=?,last_seen_at=CURRENT_TIMESTAMP,last_update_version=?,last_update_status=?,last_update_at=?,rollback_available=? WHERE client_id=?`, version, network, ad, camera, kerberos, update.Version, update.Status, update.UpdatedAt, update.RollbackAvailable, clientID)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return sql.ErrNoRows
		}
		return nil
	}
	r, err := s.DB.ExecContext(ctx, `UPDATE clients SET version=?,network_status=?,ad_status=?,camera_status=?,kerberos_status=?,last_seen_at=CURRENT_TIMESTAMP WHERE client_id=?`, version, network, ad, camera, kerberos, clientID)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RotateClientToken(ctx context.Context, clientID, tokenHash string) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE clients SET token_hash=?,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, tokenHash, clientID)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) SetClientEnabled(ctx context.Context, clientID string, enabled bool) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE clients SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, enabled, clientID)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) Clients(ctx context.Context) ([]Client, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,client_id,token_hash,enabled,version,network_status,ad_status,camera_status,kerberos_status,last_update_version,last_update_status,last_update_at,rollback_available,created_at,last_seen_at FROM clients ORDER BY client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		var c Client
		if err = rows.Scan(&c.ID, &c.ClientID, &c.TokenHash, &c.Enabled, &c.Version, &c.NetworkStatus, &c.ADStatus, &c.CameraStatus, &c.KerberosStatus, &c.LastUpdateVersion, &c.LastUpdateStatus, &c.LastUpdateAt, &c.RollbackAvailable, &c.CreatedAt, &c.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) EnsureOIDCSubject(ctx context.Context, userID int64) (string, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var subject string
	if err = tx.QueryRowContext(ctx, `SELECT oidc_subject FROM users WHERE id=?`, userID).Scan(&subject); err != nil {
		return "", err
	}
	if subject == "" {
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err != nil {
			return "", err
		}
		subject = base64.RawURLEncoding.EncodeToString(raw)
		result, updateErr := tx.ExecContext(ctx, `UPDATE users SET oidc_subject=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND oidc_subject=''`, subject, userID)
		if updateErr != nil {
			return "", updateErr
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return "", errors.New("OIDC subject update raced")
		}
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return subject, nil
}

func (s *Store) UpsertOIDCClient(ctx context.Context, clientID, secretHash, redirectURIs, scopes string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO oidc_clients(client_id,secret_hash,redirect_uris,scopes) VALUES(?,?,?,?) ON CONFLICT(client_id) DO UPDATE SET secret_hash=excluded.secret_hash,redirect_uris=excluded.redirect_uris,scopes=excluded.scopes,enabled=1,updated_at=CURRENT_TIMESTAMP`, clientID, secretHash, redirectURIs, scopes)
	return err
}
func (s *Store) CreateOIDCClient(ctx context.Context, clientID, secretHash, redirectURIs, scopes string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO oidc_clients(client_id,secret_hash,redirect_uris,scopes) VALUES(?,?,?,?)`, clientID, secretHash, redirectURIs, scopes)
	return err
}
func (s *Store) RotateOIDCClientSecret(ctx context.Context, clientID, secretHash string) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE oidc_clients SET secret_hash=?,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, secretHash, clientID)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) OIDCClientByID(ctx context.Context, clientID string) (c OIDCClient, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT client_id,secret_hash,redirect_uris,scopes,enabled FROM oidc_clients WHERE client_id=?`, clientID).Scan(&c.ClientID, &c.SecretHash, &c.RedirectURIs, &c.Scopes, &c.Enabled)
	return
}
func (s *Store) SetOIDCClientEnabled(ctx context.Context, clientID string, enabled bool) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE oidc_clients SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, enabled, clientID)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) CreateOIDCCode(ctx context.Context, c OIDCCode) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM oidc_codes WHERE code_hash IN (SELECT code_hash FROM oidc_codes WHERE expires_at<CURRENT_TIMESTAMP LIMIT 100)`); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO oidc_codes(code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at) VALUES(?,?,?,?,?,?,?,?)`, c.CodeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scope, c.Nonce, c.CodeChallenge, c.ExpiresAt.UTC())
	return err
}
func (s *Store) ConsumeOIDCCode(ctx context.Context, codeHash, clientID, redirectURI string, now time.Time) (OIDCCode, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return OIDCCode{}, err
	}
	defer tx.Rollback()
	var c OIDCCode
	err = tx.QueryRowContext(ctx, `SELECT code_hash,client_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at FROM oidc_codes WHERE code_hash=? AND client_id=? AND redirect_uri=? AND consumed_at IS NULL AND expires_at>=?`, codeHash, clientID, redirectURI, now.UTC()).Scan(&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.Nonce, &c.CodeChallenge, &c.ExpiresAt)
	if err != nil {
		return OIDCCode{}, err
	}
	r, err := tx.ExecContext(ctx, `UPDATE oidc_codes SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL`, now.UTC(), codeHash)
	if err != nil {
		return OIDCCode{}, err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return OIDCCode{}, sql.ErrNoRows
	}
	if err = tx.Commit(); err != nil {
		return OIDCCode{}, err
	}
	return c, nil
}
