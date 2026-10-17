package database

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) CreateClientWithAudit(ctx context.Context, clientID, tokenHash, ip string) (client Client, err error) {
	if err := validateAuditIP(ip); err != nil {
		return Client{}, err
	}
	err = s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		client, err = scanPostgresClient(tx.QueryRow(ctx, "INSERT INTO clients(client_id,token_hash) VALUES($1,$2) RETURNING "+postgresClientColumns, clientID, tokenHash))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES($1,$2,$3,$4)`, "client_registered", clientID, true, ip)
		return err
	})
	return client, err
}

func (s *PostgresStore) RotateClientTokenWithAudit(ctx context.Context, clientID, tokenHash, ip string) error {
	return s.updateClientWithAudit(ctx, clientID, ip, "client_token_rotated", `UPDATE clients SET token_hash=$1,updated_at=now() WHERE client_id=$2`, tokenHash, clientID)
}

func (s *PostgresStore) SetClientEnabledWithAudit(ctx context.Context, clientID string, enabled bool, ip string) error {
	event := "client_disabled"
	if enabled {
		event = "client_enabled"
	}
	return s.updateClientWithAudit(ctx, clientID, ip, event, `UPDATE clients SET enabled=$1,updated_at=now() WHERE client_id=$2`, enabled, clientID)
}

func (s *PostgresStore) updateClientWithAudit(ctx context.Context, clientID, ip, event, query string, args ...any) error {
	if err := validateAuditIP(ip); err != nil {
		return err
	}
	return s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return sql.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log(event_type,client_id,success,ip_address) VALUES($1,$2,$3,$4)`, event, clientID, true, ip)
		return err
	})
}
