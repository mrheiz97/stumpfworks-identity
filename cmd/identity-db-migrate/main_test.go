package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/jackc/pgx/v5"
)

func TestReadBoundedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "postgres-url")
	if err := os.WriteFile(path, []byte(" postgres://fixture \n"), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := readBoundedSecret(path)
	if err != nil || value != "postgres://fixture" {
		t.Fatal("bounded URL file read changed")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maximumURLFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedSecret(path); err == nil {
		t.Fatal("oversized URL file accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, []byte("postgres://fixture"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readBoundedSecret(path); err == nil {
			t.Fatal("overly broad URL file permissions accepted")
		}
	}
}

func TestConfirmationIsCheckedBeforeURLFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-url")
	err := run([]string{"--postgres-url-file", missing, "schema"}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "confirm") {
		t.Fatal("schema confirmation was not checked before connection setup")
	}
	err = run([]string{"--postgres-url-file", missing, "import"}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "confirm") {
		t.Fatal("import confirmation was not checked before connection setup")
	}
}

func TestOpenReadOnlySQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.db")
	seed, err := openWritableFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	seed.Close()
	readOnly, err := openReadOnlySQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	var value string
	if err := readOnly.QueryRow("SELECT value FROM fixture").Scan(&value); err != nil || value != "unchanged" {
		t.Fatal("read-only snapshot read failed")
	}
	if _, err := readOnly.Exec("UPDATE fixture SET value='changed'"); err == nil {
		t.Fatal("SQLite snapshot was writable")
	}
}

func TestMigrationCLIRehearsal(t *testing.T) {
	dsn := os.Getenv("IDENTITY_TEST_POSTGRES_URL")
	parsed, err := url.Parse(dsn)
	if dsn == "" || err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() != "55441" || parsed.Path != "/postgres" {
		t.Skip("disposable loopback PostgreSQL test database not configured")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("identity_migration_cli_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	directory := t.TempDir()
	urlPath := filepath.Join(directory, "postgres-url")
	if err := os.WriteFile(urlPath, []byte(parsed.String()), 0600); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(directory, "source.db")
	source, err := database.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	user, err := source.CreateUser(ctx, "migration-cli-user", "Migration CLI User", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.CreateBadge(ctx, user.ID, "synthetic-hash", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	common := []string{"--postgres-url-file", urlPath, "--allow-insecure", "--source", sourcePath, "--max-rows", "100"}
	if err := run(append(common, "--confirm", "create-empty-identity-schema", "schema"), &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if err := run(append(common, "--confirm", "import-stopped-snapshot", "import"), &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := run(append(common, "reconcile"), &output); err != nil || !strings.Contains(output.String(), "reconcile=verified") {
		t.Fatal("CLI reconciliation failed")
	}
	if _, err := admin.Exec(ctx, "UPDATE "+identifier+".users SET display_name='changed'"); err != nil {
		t.Fatal(err)
	}
	if err := run(append(common, "reconcile"), &strings.Builder{}); err == nil {
		t.Fatal("CLI reconciliation accepted changed target")
	}
}

func openWritableFixture(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("CREATE TABLE fixture(value TEXT); INSERT INTO fixture VALUES('unchanged')")
	return db, err
}
