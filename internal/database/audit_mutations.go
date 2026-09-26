package database

import (
	"context"
	"database/sql"
	"errors"
	"net"
)

// WriteAudit is the error-returning path for future consumer integration.
// Existing Audit callers keep their current policy until explicitly migrated.
func (s *Store) WriteAudit(ctx context.Context, event Audit) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,client_id,success,ip_address,details) VALUES(?,?,?,?,?,?,?)`, event.EventType, event.BadgeID, event.Username, event.ClientID, event.Success, event.IPAddress, event.Details)
	return err
}

func lostBadgeAudit(username, code, ip string) (Audit, error) {
	if ip != "" && net.ParseIP(ip) == nil {
		return Audit{}, errors.New("audit IP must be an address or empty")
	}
	return Audit{EventType: "badge_self_service_revoked", BadgeID: code, Username: username, Success: true, IPAddress: ip, Details: "lost_badge"}, nil
}

// RevokeActiveBadgeForUserWithAudit requires an authenticated consumer-owned
// user ID. Both the state change and its application-owned security event commit
// together; audit failure leaves the badge active. It is not runtime-wired yet.
func (s *Store) RevokeActiveBadgeForUserWithAudit(ctx context.Context, badgeID, userID int64, ip string) (UserBadge, error) {
	if _, err := lostBadgeAudit("", "", ip); err != nil {
		return UserBadge{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return UserBadge{}, err
	}
	defer tx.Rollback()
	var b UserBadge
	var username string
	err = tx.QueryRowContext(ctx, `SELECT b.id,b.badge_code,b.description,b.created_at,b.last_used_at,u.username FROM badges b JOIN users u ON u.id=b.user_id WHERE b.id=? AND b.user_id=? AND b.enabled=1`, badgeID, userID).Scan(&b.ID, &b.BadgeCode, &b.Description, &b.CreatedAt, &b.LastUsedAt, &username)
	if err != nil {
		return UserBadge{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE badges SET enabled=0,revoked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=? AND enabled=1`, badgeID, userID)
	if err != nil {
		return UserBadge{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return UserBadge{}, err
	}
	if changed != 1 {
		return UserBadge{}, sql.ErrNoRows
	}
	event, _ := lostBadgeAudit(username, b.BadgeCode, ip)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address,details) VALUES(?,?,?,?,?,?)`, event.EventType, event.BadgeID, event.Username, event.Success, event.IPAddress, event.Details); err != nil {
		return UserBadge{}, err
	}
	if err := tx.Commit(); err != nil {
		return UserBadge{}, err
	}
	return b, nil
}

func (s *Store) ActivatePendingBadgeForUserWithAudit(ctx context.Context, badgeID, userID int64, ip string) error {
	if ip != "" && net.ParseIP(ip) == nil {
		return errors.New("audit IP must be an address or empty")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var code, username string
	if err := tx.QueryRowContext(ctx, `SELECT b.badge_code,u.username FROM badges b JOIN users u ON u.id=b.user_id WHERE b.id=? AND b.user_id=? AND b.enabled=0 AND b.activation_pending=1`, badgeID, userID).Scan(&code, &username); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE badges SET enabled=1,activation_pending=0,revoked_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=? AND enabled=0 AND activation_pending=1`, badgeID, userID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,badge_id,username,success,ip_address,details) VALUES(?,?,?,?,?,?)`, "badge_self_service_activated", code, username, true, ip, "replacement_badge"); err != nil {
		return err
	}
	return tx.Commit()
}
