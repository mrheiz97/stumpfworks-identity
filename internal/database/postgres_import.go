package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"time"

	"github.com/jackc/pgx/v5"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var ErrImportFailed = errors.New("Identity import failed; verify target state before retry")

var importTables = []string{"users", "badges", "audit_log", "clients", "self_service_sessions", "oidc_clients", "oidc_codes"}

const maximumImportRowBytes = 256 << 10
const maximumImportBytes = 128 << 20

// ImportSQLite transfers a consistent SQLite snapshot into an already migrated,
// empty PostgreSQL target. It never applies migrations, overwrites data, or
// changes source records. Callers must stop application writes before cutover.
// Returned counts are aggregate-only; raw DB errors may contain secret values
// and are intentionally not returned. Callback failures roll back all rows;
// a lost commit response requires target reconciliation before retry.
func (s *PostgresStore) ImportSQLite(ctx context.Context, source *sql.DB, maximumRows int64) (result map[string]int64, resultErr error) {
	if ctx == nil || source == nil || maximumRows < 1 || maximumRows > 1000000 {
		return nil, errors.New("import requires context, source and row limit 1..1000000")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	defer func() {
		if resultErr != nil && ctx.Err() != nil {
			resultErr = ctx.Err()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := source.Conn(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrImportFailed
	}
	defer connection.Close()
	previousLimit, err := sqlite.Limit(connection, sqlite3.SQLITE_LIMIT_LENGTH, -1)
	if err != nil {
		return nil, ErrImportFailed
	}
	effectiveLimit := previousLimit
	if effectiveLimit > maximumImportRowBytes {
		effectiveLimit = maximumImportRowBytes
	}
	if _, err := sqlite.Limit(connection, sqlite3.SQLITE_LIMIT_LENGTH, effectiveLimit); err != nil {
		return nil, ErrImportFailed
	}
	defer func() {
		if _, err := sqlite.Limit(connection, sqlite3.SQLITE_LIMIT_LENGTH, previousLimit); err != nil {
			// Do not return a connection with a changed limit to the caller's pool.
			_ = connection.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	snapshot, err := connection.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrImportFailed
	}
	defer snapshot.Rollback()
	tables, err := snapshot.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*'")
	if err != nil {
		return nil, ErrImportFailed
	}
	known := make(map[string]bool, len(importTables))
	for _, name := range importTables {
		known[name] = true
	}
	var tableCount int
	for tables.Next() {
		var name string
		if tables.Scan(&name) != nil || !known[name] {
			tables.Close()
			return nil, ErrImportFailed
		}
		tableCount++
	}
	err = tables.Err()
	tables.Close()
	if err != nil || tableCount != len(importTables) {
		return nil, ErrImportFailed
	}
	counts := make(map[string]int64)
	var total int64
	var totalBytes int64
	err = s.pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		// The target must be dedicated to Identity. Locks prevent concurrent writes
		// while emptiness, copy and row counts are checked.
		for _, table := range importTables {
			if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{table}.Sanitize()+" IN ACCESS EXCLUSIVE MODE"); err != nil {
				return err
			}
			var existing int64
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&existing); err != nil {
				return err
			}
			if existing != 0 {
				return ErrImportFailed
			}
		}
		for _, table := range importTables {
			if err := s.importTable(ctx, tx, snapshot, table, maximumRows, &total, &totalBytes, counts); err != nil {
				return err
			}
		}
		var ambiguous bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users GROUP BY "+postgresFoldUsername+" HAVING count(*)>1)").Scan(&ambiguous); err != nil {
			return err
		}
		if ambiguous {
			return ErrImportFailed
		}
		for _, table := range []string{"users", "badges", "audit_log", "clients"} {
			var watermark int64
			if err := snapshot.QueryRowContext(ctx, "SELECT seq FROM sqlite_sequence WHERE name=?", table).Scan(&watermark); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if watermark < 0 {
				return ErrImportFailed
			}
			// Identity sequences are not transactional; a failed final commit may
			// leave harmless gaps, never source ID reassignment or target records.
			// Preserve SQLite AUTOINCREMENT high-water marks, including deleted IDs.
			if _, err := tx.Exec(ctx, "SELECT setval(pg_get_serial_sequence($1,'id'),GREATEST(COALESCE((SELECT max(id) FROM "+pgx.Identifier{table}.Sanitize()+"),0),$2::bigint,1),($2::bigint>0 OR (SELECT count(*)>0 FROM "+pgx.Identifier{table}.Sanitize()+")))", table, watermark); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrImportFailed
	}
	return counts, nil
}

func (s *PostgresStore) importTable(ctx context.Context, target pgx.Tx, snapshot *sql.Tx, table string, limit int64, total, totalBytes *int64, counts map[string]int64) error {
	metadata, err := target.Query(ctx, "SELECT column_name,data_type FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 ORDER BY ordinal_position", table)
	if err != nil {
		return err
	}
	var columns, types []string
	for metadata.Next() {
		var name, kind string
		if err := metadata.Scan(&name, &kind); err != nil {
			metadata.Close()
			return err
		}
		columns = append(columns, name)
		types = append(types, kind)
	}
	err = metadata.Err()
	metadata.Close()
	if err != nil {
		return err
	}
	if len(columns) == 0 {
		return ErrImportFailed
	}
	// Refuse newer/unknown source fields instead of silently losing them.
	sourceMetadata, err := snapshot.QueryContext(ctx, "PRAGMA table_xinfo("+pgx.Identifier{table}.Sanitize()+")")
	if err != nil {
		return err
	}
	sourceColumns := make(map[string]bool)
	for sourceMetadata.Next() {
		var ordinal, required, primary, hidden int
		var name, kind string
		var defaultValue any
		if err := sourceMetadata.Scan(&ordinal, &name, &kind, &required, &defaultValue, &primary, &hidden); err != nil {
			sourceMetadata.Close()
			return err
		}
		if hidden != 0 {
			sourceMetadata.Close()
			return ErrImportFailed
		}
		sourceColumns[name] = true
	}
	err = sourceMetadata.Err()
	sourceMetadata.Close()
	if err != nil {
		return err
	}
	if len(sourceColumns) != len(columns) {
		return ErrImportFailed
	}
	for _, name := range columns {
		if !sourceColumns[name] {
			return ErrImportFailed
		}
	}
	var projection string
	for i, name := range columns {
		if i > 0 {
			projection += ","
		}
		projection += pgx.Identifier{name}.Sanitize()
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
	rows, err := snapshot.QueryContext(ctx, "SELECT "+projection+" FROM "+pgx.Identifier{table}.Sanitize()+" ORDER BY "+sourceOrder)
	if err != nil {
		return err
	}
	defer rows.Close()
	var copied int64
	sourceDigest := sha256.New()
	source := pgx.CopyFromFunc(func() ([]any, error) {
		if !rows.Next() {
			return nil, rows.Err()
		}
		*total++
		if *total > limit {
			return nil, ErrImportFailed
		}
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		for i, value := range values {
			normalized, err := normalizeSQLiteValue(value, types[i])
			if err != nil {
				return nil, err
			}
			values[i] = normalized
			switch v := normalized.(type) {
			case string:
				*totalBytes += int64(len(v))
			case []byte:
				*totalBytes += int64(len(v))
			default:
				*totalBytes += 16
			}
		}
		if *totalBytes > maximumImportBytes {
			return nil, ErrImportFailed
		}
		if err := hashImportRow(sourceDigest, values); err != nil {
			return nil, err
		}
		copied++
		return values, nil
	})
	inserted, err := target.CopyFrom(ctx, pgx.Identifier{table}, columns, source)
	if err != nil {
		return err
	}
	if inserted != copied {
		return ErrImportFailed
	}
	var expected int64
	if err := snapshot.QueryRowContext(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&expected); err != nil {
		return err
	}
	if expected != inserted {
		return ErrImportFailed
	}
	// Compare every normalized field before commit without exposing any values
	// or credential-derived digests to logs/callers.
	verification, err := target.Query(ctx, "SELECT "+projection+" FROM "+pgx.Identifier{table}.Sanitize()+" ORDER BY "+targetOrder)
	if err != nil {
		return err
	}
	defer verification.Close()
	targetDigest := sha256.New()
	var verified int64
	for verification.Next() {
		values, err := verification.Values()
		if err != nil {
			return err
		}
		for i, value := range values {
			values[i], err = normalizeSQLiteValue(value, types[i])
			if err != nil {
				return err
			}
		}
		if err := hashImportRow(targetDigest, values); err != nil {
			return err
		}
		verified++
	}
	if verification.Err() != nil || verified != inserted || string(sourceDigest.Sum(nil)) != string(targetDigest.Sum(nil)) {
		return ErrImportFailed
	}
	counts[table] = inserted
	return nil
}

func hashImportRow(digest hash.Hash, values []any) error {
	encoded, err := json.Marshal(values)
	if err != nil {
		return ErrImportFailed
	}
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(encoded)))
	digest.Write(size[:])
	digest.Write(encoded)
	return nil
}

func normalizeSQLiteValue(value any, targetType string) (any, error) {
	if value == nil {
		return nil, nil
	}
	if targetType == "boolean" {
		switch v := value.(type) {
		case bool:
			return v, nil
		case int64:
			if v == 0 {
				return false, nil
			}
			if v == 1 {
				return true, nil
			}
		}
		return nil, ErrImportFailed
	}
	if targetType == "timestamp with time zone" {
		if v, ok := value.(time.Time); ok {
			return v.UTC().Truncate(time.Microsecond), nil
		}
		var text string
		switch v := value.(type) {
		case string:
			text = v
		case []byte:
			text = string(v)
		default:
			return nil, ErrImportFailed
		}
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999-0700 MST", "2006-01-02 15:04:05.999999999"} {
			if parsed, err := time.Parse(layout, text); err == nil {
				return parsed.UTC().Truncate(time.Microsecond), nil
			}
		}
		return nil, ErrImportFailed
	}
	return value, nil
}
