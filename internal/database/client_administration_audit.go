package database

import (
	"context"
	"database/sql"
)

func scanSQLiteClient(row *sql.Row) (Client, error) {
	var client Client
	err := row.Scan(&client.ID, &client.ClientID, &client.TokenHash, &client.AuthMode, &client.Enabled, &client.Version, &client.NetworkStatus, &client.ADStatus, &client.CameraStatus, &client.KerberosStatus, &client.LastUpdateVersion, &client.LastUpdateStatus, &client.LastUpdateAt, &client.RollbackAvailable, &client.CreatedAt, &client.LastSeenAt)
	return client, err
}

func (s *Store) CreateClientWithAudit(ctx context.Context, clientID, tokenHash, ip string) (Client, error) {
	if err := validateAuditIP(ip); err != nil {
		return Client{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Client{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO clients(client_id,token_hash) VALUES(?,?)`, clientID, tokenHash); err != nil {
		return Client{}, err
	}
	client, err := scanSQLiteClient(tx.QueryRowContext(ctx, `SELECT id,client_id,token_hash,auth_mode,enabled,version,network_status,ad_status,camera_status,kerberos_status,last_update_version,last_update_status,last_update_at,rollback_available,created_at,last_seen_at FROM clients WHERE client_id=?`, clientID))
	if err != nil {
		return Client{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES(?,?,?,?)`, "client_registered", clientID, true, ip); err != nil {
		return Client{}, err
	}
	if err := tx.Commit(); err != nil {
		return Client{}, err
	}
	return client, nil
}

func (s *Store) RotateClientTokenWithAudit(ctx context.Context, clientID, tokenHash, ip string) error {
	return s.updateClientWithAudit(ctx, clientID, ip, "client_token_rotated", `UPDATE clients SET token_hash=?,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, tokenHash, clientID)
}

func (s *Store) SetClientEnabledWithAudit(ctx context.Context, clientID string, enabled bool, ip string) error {
	event := "client_disabled"
	if enabled {
		event = "client_enabled"
	}
	return s.updateClientWithAudit(ctx, clientID, ip, event, `UPDATE clients SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE client_id=?`, enabled, clientID)
}

func (s *Store) updateClientWithAudit(ctx context.Context, clientID, ip, event, query string, args ...any) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES(?,?,?,?)`, event, clientID, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}
