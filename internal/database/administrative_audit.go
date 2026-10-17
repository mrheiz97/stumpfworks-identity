package database

import (
	"context"
	"database/sql"
)

func scanSQLiteUser(row *sql.Row) (User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.DirectoryDN, &user.PINHash, &user.PINEnabled, &user.OIDCSubject, &user.CreatedAt)
	return user, err
}

func scanSQLiteBadge(row *sql.Row) (Badge, error) {
	var badge Badge
	err := row.Scan(&badge.ID, &badge.BadgeCode, &badge.UserID, &badge.Username, &badge.DisplayName, &badge.PINHash, &badge.TokenHash, &badge.Enabled, &badge.ActivationPending, &badge.Description, &badge.CreatedAt, &badge.LastUsedAt, &badge.RevokedAt)
	return badge, err
}

func (s *Store) CreateUserWithAudit(ctx context.Context, username, displayName, directoryDN, eventType, ip string) (User, error) {
	if err := validateAuditIP(ip); err != nil {
		return User{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO users(username,display_name,directory_dn) VALUES(?,?,?)`, username, displayName, directoryDN)
	if err != nil {
		return User{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return User{}, err
	}
	user, err := scanSQLiteUser(tx.QueryRowContext(ctx, `SELECT id,username,display_name,directory_dn,pin_hash,pin_hash!='',oidc_subject,created_at FROM users WHERE id=?`, id))
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES(?,?,?,?)`, eventType, user.Username, true, ip); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) CreateBadgeWithAudit(ctx context.Context, userID int64, hash, description, ip string) (Badge, error) {
	if err := validateAuditIP(ip); err != nil {
		return Badge{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Badge{}, err
	}
	defer tx.Rollback()
	code, err := s.nextCode(ctx, tx)
	if err != nil {
		return Badge{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO badges(badge_code,user_id,token_hash,description) VALUES(?,?,?,?)`, code, userID, hash, description)
	if err != nil {
		return Badge{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Badge{}, err
	}
	badge, err := scanSQLiteBadge(tx.QueryRowContext(ctx, `SELECT b.id,b.badge_code,b.user_id,u.username,u.display_name,u.pin_hash,b.token_hash,b.enabled,b.activation_pending,b.description,b.created_at,b.last_used_at,b.revoked_at FROM badges b JOIN users u ON u.id=b.user_id WHERE b.id=?`, id))
	if err != nil {
		return Badge{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address) VALUES(?,?,?,?,?)`, "badge_created", badge.BadgeCode, badge.Username, true, ip); err != nil {
		return Badge{}, err
	}
	if err := tx.Commit(); err != nil {
		return Badge{}, err
	}
	return badge, nil
}

func (s *Store) RevokeBadgeWithAudit(ctx context.Context, badgeID int64, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var code, username string
	if err := tx.QueryRowContext(ctx, `SELECT b.badge_code,u.username FROM badges b JOIN users u ON u.id=b.user_id WHERE b.id=? AND b.enabled=1`, badgeID).Scan(&code, &username); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE badges SET enabled=0,activation_pending=0,revoked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND enabled=1`, badgeID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address) VALUES(?,?,?,?,?)`, "badge_revoked", code, username, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReplaceBadgePendingWithAudit(ctx context.Context, oldID int64, tokenHash, description, ip string) (Badge, error) {
	if err := validateAuditIP(ip); err != nil {
		return Badge{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Badge{}, err
	}
	defer tx.Rollback()
	var userID int64
	var oldCode, username string
	if err := tx.QueryRowContext(ctx, `SELECT b.user_id,b.badge_code,u.username FROM badges b JOIN users u ON u.id=b.user_id WHERE b.id=? AND b.enabled=1`, oldID).Scan(&userID, &oldCode, &username); err != nil {
		return Badge{}, err
	}
	code, err := s.nextCode(ctx, tx)
	if err != nil {
		return Badge{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE badges SET enabled=0,activation_pending=0,revoked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND enabled=1`, oldID)
	if err != nil {
		return Badge{}, err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return Badge{}, sql.ErrNoRows
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO badges(badge_code,user_id,token_hash,enabled,activation_pending,description) VALUES(?,?,?,0,1,?)`, code, userID, tokenHash, description)
	if err != nil {
		return Badge{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Badge{}, err
	}
	replacement, err := scanSQLiteBadge(tx.QueryRowContext(ctx, `SELECT b.id,b.badge_code,b.user_id,u.username,u.display_name,u.pin_hash,b.token_hash,b.enabled,b.activation_pending,b.description,b.created_at,b.last_used_at,b.revoked_at FROM badges b JOIN users u ON u.id=b.user_id WHERE b.id=?`, id))
	if err != nil {
		return Badge{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address,details) VALUES(?,?,?,?,?,?)`, "badge_replaced", oldCode, username, true, ip, "new_badge="+replacement.BadgeCode); err != nil {
		return Badge{}, err
	}
	if err := tx.Commit(); err != nil {
		return Badge{}, err
	}
	return replacement, nil
}
