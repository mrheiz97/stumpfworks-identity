package database

import (
	"context"
	"database/sql"
	"time"
)

// ClientCertificateSummary projects only operational metadata. Credential IDs,
// fingerprints, serials, issuer identifiers and enrollment tokens stay private
// to the credential lifecycle boundary.
type ClientCertificateSummary struct {
	ClientID                       string
	Status                         string
	IssuedAt, ExpiresAt, CreatedAt sql.NullTime
	PendingActivation              bool
}

// Active credentials take precedence even when expired. Pending renewal must
// not hide the currently authoritative certificate. Without either, display
// the latest historical credential (including revocation).
const clientCertificateSummaryQuery = `SELECT c.client_id,COALESCE(d.status,''),d.issued_at,d.expires_at,d.created_at,
 EXISTS(SELECT 1 FROM client_device_credentials p WHERE p.client_id=c.client_id AND p.status='pending' AND p.created_at>$1 AND p.expires_at>$2)
 FROM clients c LEFT JOIN client_device_credentials d ON d.id=(
 SELECT x.id FROM client_device_credentials x WHERE x.client_id=c.client_id
 ORDER BY CASE x.status WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,x.created_at DESC,x.id DESC LIMIT 1)
 ORDER BY c.client_id`

type certificateSummaryRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func scanCertificateSummaries(rows certificateSummaryRows) ([]ClientCertificateSummary, error) {
	out := []ClientCertificateSummary{}
	for rows.Next() {
		var v ClientCertificateSummary
		if err := rows.Scan(&v.ClientID, &v.Status, &v.IssuedAt, &v.ExpiresAt, &v.CreatedAt, &v.PendingActivation); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) ClientCertificateSummaries(ctx context.Context, now time.Time) ([]ClientCertificateSummary, error) {
	rows, err := s.DB.QueryContext(ctx, clientCertificateSummaryQuery, now.Add(-ClientDeviceActivationWindow).UTC(), now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCertificateSummaries(rows)
}
func (s *PostgresStore) ClientCertificateSummaries(ctx context.Context, now time.Time) ([]ClientCertificateSummary, error) {
	rows, err := s.pool.Native().Query(ctx, clientCertificateSummaryQuery, now.Add(-ClientDeviceActivationWindow).UTC(), now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCertificateSummaries(rows)
}
