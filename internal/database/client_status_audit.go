package database

import (
	"context"
	"database/sql"
)

func (s *Store) UpdateClientStatusWithUpdateAndTokenFallbackAudit(ctx context.Context, clientID, version, network, ad, camera, kerberos string, update *ClientUpdate, ip string) error {
	if validateAuditIP(ip) != nil {
		return ErrInvalidClientDeviceCredential
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `UPDATE clients SET version=?,network_status=?,ad_status=?,camera_status=?,kerberos_status=?,last_seen_at=CURRENT_TIMESTAMP WHERE client_id=?`
	args := []any{version, network, ad, camera, kerberos, clientID}
	if update != nil {
		query = `UPDATE clients SET version=?,network_status=?,ad_status=?,camera_status=?,kerberos_status=?,last_seen_at=CURRENT_TIMESTAMP,last_update_version=?,last_update_status=?,last_update_at=?,rollback_available=? WHERE client_id=?`
		args = []any{version, network, ad, camera, kerberos, update.Version, update.Status, update.UpdatedAt.UTC(), update.RollbackAvailable, clientID}
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES(?,?,?,?)`, "client_certificate_token_fallback", clientID, true, ip); err != nil {
		return err
	}
	return tx.Commit()
}
