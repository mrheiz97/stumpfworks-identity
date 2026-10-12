package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"hash"
	"time"

	"github.com/jackc/pgx/v5"
)

func newImportDigest() hash.Hash { return sha256.New() }

func digestSQLiteRows(rows *sql.Rows, types []string, digest hash.Hash, remainingRows, remainingBytes int64) (int64, int64, error) {
	var count, bytes int64
	for rows.Next() {
		count++
		if count > remainingRows {
			return 0, 0, ErrImportFailed
		}
		values := make([]any, len(types))
		destinations := make([]any, len(types))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return 0, 0, err
		}
		for i := range values {
			normalized, err := normalizeSQLiteValue(values[i], types[i])
			if err != nil {
				return 0, 0, err
			}
			values[i] = normalized
			switch value := normalized.(type) {
			case string:
				bytes += int64(len(value))
			case []byte:
				bytes += int64(len(value))
			default:
				bytes += 16
			}
		}
		if bytes > remainingBytes || hashImportRow(digest, values) != nil {
			return 0, 0, ErrImportFailed
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	return count, bytes, nil
}

// ReconcileSQLite proves that every normalized source field is present in the
// PostgreSQL target. It returns aggregate row counts only; record values and
// digests never leave this boundary. Callers must keep application writes
// stopped for the duration of reconciliation.
func (s *PostgresStore) ReconcileSQLite(ctx context.Context, source *sql.DB, maximumRows int64) (map[string]int64, error) {
	if ctx == nil || source == nil || maximumRows < 1 || maximumRows > 1000000 {
		return nil, errors.New("reconciliation requires context, source and row limit 1..1000000")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	snapshot, err := source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, reconciliationError(ctx)
	}
	defer snapshot.Rollback()
	if err := validateSQLiteImportShape(ctx, snapshot); err != nil {
		return nil, reconciliationError(ctx)
	}
	counts := make(map[string]int64, len(importTables))
	var total, totalBytes int64
	err = s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		for _, table := range importTables {
			if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{table}.Sanitize()+" IN SHARE MODE"); err != nil {
				return err
			}
		}
		for _, table := range importTables {
			count, bytes, err := reconcileTable(ctx, tx, snapshot, table, maximumRows-total, maximumImportBytes-totalBytes)
			if err != nil {
				return err
			}
			total += count
			totalBytes += bytes
			counts[table] = count
		}
		return nil
	})
	if err != nil {
		return nil, reconciliationError(ctx)
	}
	return counts, nil
}

func reconciliationError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrImportFailed
}

func validateSQLiteImportShape(ctx context.Context, snapshot *sql.Tx) error {
	rows, err := snapshot.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*'")
	if err != nil {
		return err
	}
	defer rows.Close()
	known := make(map[string]bool, len(importTables))
	for _, table := range importTables {
		known[table] = true
	}
	var count int
	for rows.Next() {
		var table string
		if rows.Scan(&table) != nil || !known[table] {
			return ErrImportFailed
		}
		count++
	}
	if rows.Err() != nil || count != len(importTables) {
		return ErrImportFailed
	}
	return nil
}

func reconcileTable(ctx context.Context, target pgx.Tx, source *sql.Tx, table string, remainingRows, remainingBytes int64) (int64, int64, error) {
	if remainingRows < 0 || remainingBytes < 0 {
		return 0, 0, ErrImportFailed
	}
	metadata, err := target.Query(ctx, "SELECT column_name,data_type FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 ORDER BY ordinal_position", table)
	if err != nil {
		return 0, 0, err
	}
	var columns, types []string
	for metadata.Next() {
		var column, kind string
		if err := metadata.Scan(&column, &kind); err != nil {
			metadata.Close()
			return 0, 0, err
		}
		columns, types = append(columns, column), append(types, kind)
	}
	err = metadata.Err()
	metadata.Close()
	if err != nil || len(columns) == 0 {
		return 0, 0, ErrImportFailed
	}
	sourceMetadata, err := source.QueryContext(ctx, "PRAGMA table_xinfo("+pgx.Identifier{table}.Sanitize()+")")
	if err != nil {
		return 0, 0, err
	}
	seen := make(map[string]bool, len(columns))
	for sourceMetadata.Next() {
		var ordinal, required, primary, hidden int
		var name, kind string
		var defaultValue any
		if err := sourceMetadata.Scan(&ordinal, &name, &kind, &required, &defaultValue, &primary, &hidden); err != nil || hidden != 0 {
			sourceMetadata.Close()
			return 0, 0, ErrImportFailed
		}
		seen[name] = true
	}
	err = sourceMetadata.Err()
	sourceMetadata.Close()
	if err != nil || len(seen) != len(columns) {
		return 0, 0, ErrImportFailed
	}
	projection := ""
	for i, column := range columns {
		if !seen[column] {
			return 0, 0, ErrImportFailed
		}
		if i > 0 {
			projection += ","
		}
		projection += pgx.Identifier{column}.Sanitize()
	}
	key := "id"
	if table == "oidc_clients" {
		key = "client_id"
	} else if table == "oidc_codes" {
		key = "code_hash"
	}
	sourceOrder, targetOrder := pgx.Identifier{key}.Sanitize(), pgx.Identifier{key}.Sanitize()
	if table == "self_service_sessions" || table == "oidc_clients" || table == "oidc_codes" {
		sourceOrder += " COLLATE BINARY"
		targetOrder += ` COLLATE "C"`
	}
	sourceRows, err := source.QueryContext(ctx, "SELECT "+projection+" FROM "+pgx.Identifier{table}.Sanitize()+" ORDER BY "+sourceOrder)
	if err != nil {
		return 0, 0, err
	}
	sourceDigest := newImportDigest()
	count, bytes, err := digestSQLiteRows(sourceRows, types, sourceDigest, remainingRows, remainingBytes)
	sourceRows.Close()
	if err != nil {
		return 0, 0, err
	}
	targetRows, err := target.Query(ctx, "SELECT "+projection+" FROM "+pgx.Identifier{table}.Sanitize()+" ORDER BY "+targetOrder)
	if err != nil {
		return 0, 0, err
	}
	targetDigest := newImportDigest()
	var targetCount int64
	for targetRows.Next() {
		values, err := targetRows.Values()
		if err != nil {
			targetRows.Close()
			return 0, 0, err
		}
		for i := range values {
			values[i], err = normalizeSQLiteValue(values[i], types[i])
			if err != nil {
				targetRows.Close()
				return 0, 0, err
			}
		}
		if err := hashImportRow(targetDigest, values); err != nil {
			targetRows.Close()
			return 0, 0, err
		}
		targetCount++
	}
	err = targetRows.Err()
	targetRows.Close()
	if err != nil || targetCount != count || string(targetDigest.Sum(nil)) != string(sourceDigest.Sum(nil)) {
		return 0, 0, ErrImportFailed
	}
	return count, bytes, nil
}
