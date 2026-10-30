package database

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) UpdateClientStatusWithUpdateAndTokenFallbackAudit(ctx context.Context, clientID, version, network, ad, camera, kerberos string, update *ClientUpdate, ip string) error {
	if validateAuditIP(ip) != nil {
		return ErrInvalidClientDeviceCredential
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		query := `UPDATE clients SET version=$1,network_status=$2,ad_status=$3,camera_status=$4,kerberos_status=$5,last_seen_at=now() WHERE client_id=$6`
		args := []any{version, network, ad, camera, kerberos, clientID}
		if update != nil {
			query = `UPDATE clients SET version=$1,network_status=$2,ad_status=$3,camera_status=$4,kerberos_status=$5,last_seen_at=now(),last_update_version=$7,last_update_status=$8,last_update_at=$9,rollback_available=$10 WHERE client_id=$6`
			args = append(args, update.Version, update.Status, update.UpdatedAt.UTC(), update.RollbackAvailable)
		}
		result, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES($1,$2,$3,$4)`, "client_certificate_token_fallback", clientID, true, ip)
		return err
	})
}
