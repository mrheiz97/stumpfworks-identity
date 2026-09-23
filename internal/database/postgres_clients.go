package database

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
)

const postgresClientColumns = "id,client_id,token_hash,enabled,version,network_status,ad_status,camera_status,kerberos_status,last_update_version,last_update_status,last_update_at,rollback_available,created_at,last_seen_at"

func scanPostgresClient(row pgx.Row) (Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.ClientID, &c.TokenHash, &c.Enabled, &c.Version, &c.NetworkStatus, &c.ADStatus, &c.CameraStatus, &c.KerberosStatus, &c.LastUpdateVersion, &c.LastUpdateStatus, &c.LastUpdateAt, &c.RollbackAvailable, &c.CreatedAt, &c.LastSeenAt)
	return c, postgresNotFound(err)
}

func (s *PostgresStore) CreateClient(ctx context.Context, clientID, hash string) (Client, error) {
	return scanPostgresClient(s.pool.Native().QueryRow(ctx, "INSERT INTO clients(client_id,token_hash) VALUES($1,$2) RETURNING "+postgresClientColumns, clientID, hash))
}

func (s *PostgresStore) ClientByID(ctx context.Context, clientID string) (Client, error) {
	return scanPostgresClient(s.pool.Native().QueryRow(ctx, "SELECT "+postgresClientColumns+" FROM clients WHERE client_id=$1", clientID))
}

func (s *PostgresStore) Clients(ctx context.Context) ([]Client, error) {
	rows, err := s.pool.Native().Query(ctx, "SELECT "+postgresClientColumns+" FROM clients ORDER BY client_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		client, err := scanPostgresClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateClientStatus(ctx context.Context, clientID, version, network, ad, camera, kerberos string) error {
	return s.UpdateClientStatusWithUpdate(ctx, clientID, version, network, ad, camera, kerberos, nil)
}

func (s *PostgresStore) UpdateClientStatusWithUpdate(ctx context.Context, clientID, version, network, ad, camera, kerberos string, update *ClientUpdate) error {
	query := "UPDATE clients SET version=$1,network_status=$2,ad_status=$3,camera_status=$4,kerberos_status=$5,last_seen_at=now() WHERE client_id=$6"
	args := []any{version, network, ad, camera, kerberos, clientID}
	if update != nil {
		query = "UPDATE clients SET version=$1,network_status=$2,ad_status=$3,camera_status=$4,kerberos_status=$5,last_seen_at=now(),last_update_version=$7,last_update_status=$8,last_update_at=$9,rollback_available=$10 WHERE client_id=$6"
		args = append(args, update.Version, update.Status, update.UpdatedAt.UTC(), update.RollbackAvailable)
	}
	result, err := s.pool.Native().Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) RotateClientToken(ctx context.Context, clientID, hash string) error {
	result, err := s.pool.Native().Exec(ctx, "UPDATE clients SET token_hash=$1,updated_at=now() WHERE client_id=$2", hash, clientID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) SetClientEnabled(ctx context.Context, clientID string, enabled bool) error {
	result, err := s.pool.Native().Exec(ctx, "UPDATE clients SET enabled=$1,updated_at=now() WHERE client_id=$2", enabled, clientID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return sql.ErrNoRows
	}
	return nil
}
