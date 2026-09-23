package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const postgresBadgeColumns = "b.id,b.badge_code,b.user_id,u.username,u.display_name,u.pin_hash,b.token_hash,b.enabled,b.activation_pending,b.description,b.created_at,b.last_used_at,b.revoked_at"
const postgresBadgeJoin = " FROM badges b JOIN users u ON u.id=b.user_id"

func scanPostgresBadge(row pgx.Row) (Badge, error) {
	var b Badge
	err := row.Scan(&b.ID, &b.BadgeCode, &b.UserID, &b.Username, &b.DisplayName, &b.PINHash, &b.TokenHash, &b.Enabled, &b.ActivationPending, &b.Description, &b.CreatedAt, &b.LastUsedAt, &b.RevokedAt)
	return b, postgresNotFound(err)
}

func insertPostgresBadge(ctx context.Context, tx pgx.Tx, userID int64, hash, description string, pending bool) (Badge, error) {
	var id int64
	// Sequence allocation replaces SQLite MAX(id)+1. Gaps after rollback are
	// intentional; concurrent creation cannot reuse a code or another user's ID.
	if err := tx.QueryRow(ctx, "SELECT nextval(pg_get_serial_sequence('badges','id'))").Scan(&id); err != nil {
		return Badge{}, err
	}
	code := fmt.Sprintf("SW-%04d", id)
	if _, err := tx.Exec(ctx, `INSERT INTO badges(id,badge_code,user_id,token_hash,description,enabled,activation_pending) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, code, userID, hash, description, !pending, pending); err != nil {
		return Badge{}, err
	}
	return scanPostgresBadge(tx.QueryRow(ctx, "SELECT "+postgresBadgeColumns+postgresBadgeJoin+" WHERE b.id=$1", id))
}

func (s *PostgresStore) CreateBadge(ctx context.Context, userID int64, hash, description string) (Badge, error) {
	var badge Badge
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		badge, err = insertPostgresBadge(ctx, tx, userID, hash, description, false)
		return err
	})
	return badge, err
}

func (s *PostgresStore) ReplaceBadgePending(ctx context.Context, oldID int64, hash, description string) (Badge, error) {
	var badge Badge
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var userID int64
		if err := tx.QueryRow(ctx, "SELECT user_id FROM badges WHERE id=$1 AND enabled=TRUE FOR UPDATE", oldID).Scan(&userID); err != nil {
			return postgresNotFound(err)
		}
		if _, err := tx.Exec(ctx, "UPDATE badges SET enabled=FALSE,activation_pending=FALSE,revoked_at=now(),updated_at=now() WHERE id=$1", oldID); err != nil {
			return err
		}
		var err error
		badge, err = insertPostgresBadge(ctx, tx, userID, hash, description, true)
		return err
	})
	return badge, err
}

func (s *PostgresStore) GetBadge(ctx context.Context, id int64) (Badge, error) {
	return scanPostgresBadge(s.pool.Native().QueryRow(ctx, "SELECT "+postgresBadgeColumns+postgresBadgeJoin+" WHERE b.id=$1", id))
}

func (s *PostgresStore) BadgeByCode(ctx context.Context, code string) (Badge, error) {
	return scanPostgresBadge(s.pool.Native().QueryRow(ctx, "SELECT "+postgresBadgeColumns+postgresBadgeJoin+" WHERE b.badge_code=$1", code))
}

func (s *PostgresStore) Badges(ctx context.Context) ([]Badge, error) {
	rows, err := s.pool.Native().Query(ctx, "SELECT "+postgresBadgeColumns+postgresBadgeJoin+" ORDER BY b.id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Badge{}
	for rows.Next() {
		badge, err := scanPostgresBadge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, badge)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ActiveBadgesByUser(ctx context.Context, userID int64) ([]UserBadge, error) {
	rows, err := s.pool.Native().Query(ctx, "SELECT id,badge_code,description,created_at,last_used_at FROM badges WHERE user_id=$1 AND enabled=TRUE ORDER BY id DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserBadge{}
	for rows.Next() {
		var b UserBadge
		if err := rows.Scan(&b.ID, &b.BadgeCode, &b.Description, &b.CreatedAt, &b.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeActiveBadgeForUser(ctx context.Context, badgeID, userID int64) (UserBadge, error) {
	var b UserBadge
	err := s.pool.Native().QueryRow(ctx, `UPDATE badges SET enabled=FALSE,revoked_at=now(),updated_at=now() WHERE id=$1 AND user_id=$2 AND enabled=TRUE RETURNING id,badge_code,description,created_at,last_used_at`, badgeID, userID).Scan(&b.ID, &b.BadgeCode, &b.Description, &b.CreatedAt, &b.LastUsedAt)
	return b, postgresNotFound(err)
}

func (s *PostgresStore) ActivatePendingBadgeForUser(ctx context.Context, badgeID, userID int64) error {
	result, err := s.pool.Native().Exec(ctx, `UPDATE badges SET enabled=TRUE,activation_pending=FALSE,revoked_at=NULL,updated_at=now() WHERE id=$1 AND user_id=$2 AND enabled=FALSE AND activation_pending=TRUE`, badgeID, userID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) Revoke(ctx context.Context, id int64) error {
	_, err := s.pool.Native().Exec(ctx, "UPDATE badges SET enabled=FALSE,activation_pending=FALSE,revoked_at=now(),updated_at=now() WHERE id=$1", id)
	return err
}

func (s *PostgresStore) Used(ctx context.Context, id int64) error {
	_, err := s.pool.Native().Exec(ctx, "UPDATE badges SET last_used_at=now() WHERE id=$1", id)
	return err
}

// RevokeActiveBadgeForUserWithAudit is the staged atomic equivalent of the
// SQLite API. The consumer supplies only its authenticated user ID and peer IP;
// event identity/code/reason are derived here, never from untrusted form fields.
func (s *PostgresStore) RevokeActiveBadgeForUserWithAudit(ctx context.Context, badgeID, userID int64, ip string) (UserBadge, error) {
	if _, err := lostBadgeAudit("", "", ip); err != nil {
		return UserBadge{}, err
	}
	var b UserBadge
	err := s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE badges SET enabled=FALSE,revoked_at=now(),updated_at=now() WHERE id=$1 AND user_id=$2 AND enabled=TRUE RETURNING id,badge_code,description,created_at,last_used_at`, badgeID, userID).Scan(&b.ID, &b.BadgeCode, &b.Description, &b.CreatedAt, &b.LastUsedAt); err != nil {
			return postgresNotFound(err)
		}
		var username string
		if err := tx.QueryRow(ctx, "SELECT username FROM users WHERE id=$1", userID).Scan(&username); err != nil {
			return postgresNotFound(err)
		}
		event, _ := lostBadgeAudit(username, b.BadgeCode, ip)
		_, err := tx.Exec(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address,details) VALUES($1,$2,$3,$4,$5,$6)`, event.EventType, event.BadgeID, event.Username, event.Success, event.IPAddress, event.Details)
		return err
	})
	if err != nil {
		return UserBadge{}, err
	}
	return b, nil
}
