package database

import (
	"context"
)

// WriteAudit deliberately returns errors instead of copying the legacy silent
// Audit method. Consumer failure policy must be explicit before runtime wiring.
// Database errors can include sensitive values: never log them verbatim.
func (s *PostgresStore) WriteAudit(ctx context.Context, event Audit) error {
	_, err := s.pool.Native().Exec(ctx, `INSERT INTO audit_log(event_type,badge_id,username,client_id,success,ip_address,details) VALUES($1,$2,$3,$4,$5,$6,$7)`, event.EventType, event.BadgeID, event.Username, event.ClientID, event.Success, event.IPAddress, event.Details)
	return err
}

func (s *PostgresStore) Audits(ctx context.Context) ([]Audit, error) {
	rows, err := s.pool.Native().Query(ctx, "SELECT id,event_type,badge_id,username,client_id,success,ip_address,timestamp,details FROM audit_log ORDER BY id DESC LIMIT 200")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var event Audit
		if err := rows.Scan(&event.ID, &event.EventType, &event.BadgeID, &event.Username, &event.ClientID, &event.Success, &event.IPAddress, &event.Timestamp, &event.Details); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RecentBadgeAuthByUser(ctx context.Context, username string) ([]UserAuthEvent, error) {
	rows, err := s.pool.Native().Query(ctx, "SELECT badge_id,client_id,success,timestamp FROM audit_log WHERE "+postgresFoldUsername+"="+postgresFoldArgument+" AND event_type IN ('auth_success','auth_failed') ORDER BY id DESC LIMIT 20", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserAuthEvent{}
	for rows.Next() {
		var event UserAuthEvent
		if err := rows.Scan(&event.BadgeID, &event.ClientID, &event.Success, &event.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

// Counts makes query failures visible; the legacy Stats method silently
// returns zero. Day boundaries are UTC, matching SQLite date('now').
func (s *PostgresStore) Counts(ctx context.Context) (map[string]int64, error) {
	out := make(map[string]int64)
	queries := map[string]string{
		"users":   "SELECT count(*) FROM users",
		"badges":  "SELECT count(*) FROM badges",
		"active":  "SELECT count(*) FROM badges WHERE enabled=TRUE",
		"revoked": "SELECT count(*) FROM badges WHERE enabled=FALSE",
		"today":   "SELECT count(*) FROM audit_log WHERE event_type='auth_success' AND (timestamp AT TIME ZONE 'UTC')::date=(now() AT TIME ZONE 'UTC')::date",
		"failed":  "SELECT count(*) FROM audit_log WHERE event_type='auth_failed' AND (timestamp AT TIME ZONE 'UTC')::date=(now() AT TIME ZONE 'UTC')::date",
	}
	for name, query := range queries {
		var count int64
		if err := s.pool.Native().QueryRow(ctx, query).Scan(&count); err != nil {
			return nil, err
		}
		out[name] = count
	}
	return out, nil
}
