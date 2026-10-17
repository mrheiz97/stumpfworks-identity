package database

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) CreateUserWithAudit(ctx context.Context, username, displayName, directoryDN, eventType, ip string) (User, error) {
	if err := validateAuditIP(ip); err != nil {
		return User{}, err
	}
	var user User
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		user, err = scanPostgresUser(tx.QueryRow(ctx, `INSERT INTO users(username,display_name,directory_dn) VALUES($1,$2,$3) RETURNING `+postgresUserColumns, username, displayName, directoryDN))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,username,success,ip_address) VALUES($1,$2,$3,$4)`, eventType, user.Username, true, ip)
		return err
	})
	return user, err
}

func (s *PostgresStore) CreateBadgeWithAudit(ctx context.Context, userID int64, hash, description, ip string) (Badge, error) {
	if err := validateAuditIP(ip); err != nil {
		return Badge{}, err
	}
	var badge Badge
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		badge, err = insertPostgresBadge(ctx, tx, userID, hash, description, false)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address) VALUES($1,$2,$3,$4,$5)`, "badge_created", badge.BadgeCode, badge.Username, true, ip)
		return err
	})
	return badge, err
}

func (s *PostgresStore) RevokeBadgeWithAudit(ctx context.Context, badgeID int64, ip string) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var code string
		var userID int64
		if err := tx.QueryRow(ctx, `UPDATE badges SET enabled=FALSE,activation_pending=FALSE,revoked_at=now(),updated_at=now() WHERE id=$1 AND enabled=TRUE RETURNING badge_code,user_id`, badgeID).Scan(&code, &userID); err != nil {
			return postgresNotFound(err)
		}
		var username string
		if err := tx.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, userID).Scan(&username); err != nil {
			return postgresNotFound(err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address) VALUES($1,$2,$3,$4,$5)`, "badge_revoked", code, username, true, ip)
		return err
	})
}

func (s *PostgresStore) ReplaceBadgePendingWithAudit(ctx context.Context, oldID int64, hash, description, ip string) (Badge, error) {
	if err := validateAuditIP(ip); err != nil {
		return Badge{}, err
	}
	var replacement Badge
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var userID int64
		var oldCode, username string
		if err := tx.QueryRow(ctx, `SELECT b.user_id,b.badge_code,u.username FROM badges b JOIN users u ON u.id=b.user_id WHERE b.id=$1 AND b.enabled=TRUE FOR UPDATE`, oldID).Scan(&userID, &oldCode, &username); err != nil {
			return postgresNotFound(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE badges SET enabled=FALSE,activation_pending=FALSE,revoked_at=now(),updated_at=now() WHERE id=$1`, oldID); err != nil {
			return err
		}
		var err error
		replacement, err = insertPostgresBadge(ctx, tx, userID, hash, description, true)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address,details) VALUES($1,$2,$3,$4,$5,$6)`, "badge_replaced", oldCode, username, true, ip, "new_badge="+replacement.BadgeCode)
		return err
	})
	return replacement, err
}
