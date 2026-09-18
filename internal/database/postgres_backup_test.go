package database

import (
	"context"
	"crypto/sha256"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	frameworkpg "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	"github.com/jackc/pgx/v5"
)

func testPostgresBackupRestore(t *testing.T, ctx context.Context, dsn, schema string, pool *frameworkpg.Pool) {
	t.Helper()
	if !regexp.MustCompile(`^identity_test_[0-9]+$`).MatchString(schema) {
		t.Fatal("backup rehearsal requires generated test schema")
	}
	dump := os.Getenv("IDENTITY_TEST_PG_DUMP")
	restore := os.Getenv("IDENTITY_TEST_PG_RESTORE")
	if dump == "" {
		dump, _ = exec.LookPath("pg_dump")
	}
	if restore == "" {
		restore, _ = exec.LookPath("pg_restore")
	}
	if dump == "" || restore == "" {
		t.Skip("PostgreSQL backup tools not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Port() != "55441" || u.Path != "/postgres" {
		t.Fatal("backup tools require disposable loopback database")
	}
	// Do not let inherited libpq service/host settings redirect this rehearsal.
	var environment []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(strings.SplitN(entry, "=", 2)[0]), "PG") {
			environment = append(environment, entry)
		}
	}
	user, password := "postgres", ""
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
	}
	environment = append(environment, "PGHOST=127.0.0.1", "PGPORT=55441", "PGDATABASE=postgres", "PGUSER="+user, "PGPASSWORD="+password, "PGSSLMODE=disable", "PGCONNECT_TIMEOUT=5")
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	run := func(binary string, arguments ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, binary, arguments...)
		command.Env = environment
		if _, err := command.CombinedOutput(); err != nil {
			t.Fatal("synthetic PostgreSQL backup/restore command failed")
		}
	}
	before := postgresFixtureFingerprint(t, ctx, pool)
	backup := filepath.Join(t.TempDir(), "synthetic-identity.dump")
	run(dump, "--format=custom", "--data-only", "--schema="+schema, "--exclude-table="+schema+".swf_schema_migrations", "--file="+backup)
	if _, err := pool.Native().Exec(ctx, "TRUNCATE users,badges,audit_log,clients,self_service_sessions,oidc_clients,oidc_codes RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal(err)
	}
	run(restore, "--data-only", "--exit-on-error", "--no-owner", "--no-privileges", "--dbname=postgres", "--schema="+schema, backup)
	after := postgresFixtureFingerprint(t, ctx, pool)
	for _, table := range importTables {
		if string(before[table]) != string(after[table]) {
			t.Fatal("backup restoration changed synthetic table data")
		}
	}
}

func postgresFixtureFingerprint(t *testing.T, ctx context.Context, pool *frameworkpg.Pool) map[string][]byte {
	t.Helper()
	digests := make(map[string][]byte)
	for _, table := range importTables {
		key := "id"
		if table == "oidc_clients" {
			key = "client_id"
		} else if table == "oidc_codes" {
			key = "code_hash"
		}
		rows, err := pool.Native().Query(ctx, "SELECT row_to_json(t)::text FROM "+pgx.Identifier{table}.Sanitize()+" t ORDER BY "+pgx.Identifier{key}.Sanitize())
		if err != nil {
			t.Fatal("fixture verification query failed")
		}
		digest := sha256.New()
		for rows.Next() {
			var record string
			if err := rows.Scan(&record); err != nil {
				rows.Close()
				t.Fatal("fixture verification scan failed")
			}
			if err := hashImportRow(digest, []any{record}); err != nil {
				rows.Close()
				t.Fatal(err)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal("fixture verification read failed")
		}
		digests[table] = digest.Sum(nil)
	}
	return digests
}
