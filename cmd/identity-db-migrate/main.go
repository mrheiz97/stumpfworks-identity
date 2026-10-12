package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	frameworkpg "github.com/mrheiz97/stumpfworks-framework/data/postgres"
	_ "modernc.org/sqlite"
)

const maximumURLFileBytes = 64 << 10

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("identity-db-migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	urlFile := flags.String("postgres-url-file", "", "root-readable PostgreSQL URL file")
	sourcePath := flags.String("source", "", "consistent SQLite snapshot")
	allowInsecure := flags.Bool("allow-insecure", false, "allow non-TLS PostgreSQL only for an isolated rehearsal")
	maximumRows := flags.Int64("max-rows", 1000000, "maximum aggregate source rows")
	confirmation := flags.String("confirm", "", "required exact confirmation for mutating actions")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return errors.New("usage: identity-db-migrate [options] schema|import|reconcile")
	}
	action := flags.Arg(0)
	if action != "schema" && action != "import" && action != "reconcile" {
		return errors.New("action must be schema, import, or reconcile")
	}
	if *urlFile == "" {
		return errors.New("PostgreSQL URL file is required")
	}
	postgresURL, err := readBoundedSecret(*urlFile)
	if err != nil {
		return errors.New("PostgreSQL URL file could not be read safely")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, err := frameworkpg.Open(ctx, frameworkpg.Options{
		URL: postgresURL, MaxConnections: 4, ConnectTimeout: 5 * time.Second,
		MaxMessageBytes: 16 << 20, AllowInsecure: *allowInsecure,
	})
	if err != nil {
		return errors.New("PostgreSQL connection failed")
	}
	defer pool.Close()
	if action == "schema" {
		if *confirmation != "create-empty-identity-schema" {
			return errors.New("schema requires --confirm create-empty-identity-schema")
		}
		if err := database.MigratePostgres(ctx, pool); err != nil {
			return errors.New("PostgreSQL schema migration failed")
		}
		fmt.Fprintln(output, "schema=ready")
		return nil
	}
	source, err := openReadOnlySQLite(*sourcePath)
	if err != nil {
		return errors.New("SQLite snapshot could not be opened read-only")
	}
	defer source.Close()
	store, err := database.NewPostgresStore(pool)
	if err != nil {
		return errors.New("PostgreSQL store initialization failed")
	}
	var counts map[string]int64
	if action == "import" {
		if *confirmation != "import-stopped-snapshot" {
			return errors.New("import requires --confirm import-stopped-snapshot")
		}
		counts, err = store.ImportSQLite(ctx, source, *maximumRows)
		if err != nil {
			return errors.New("import failed; reconcile target state before retry")
		}
	} else {
		counts, err = store.ReconcileSQLite(ctx, source, *maximumRows)
		if err != nil {
			return errors.New("reconciliation failed")
		}
	}
	keys := make([]string, 0, len(counts))
	for table := range counts {
		keys = append(keys, table)
	}
	sort.Strings(keys)
	for _, table := range keys {
		fmt.Fprintf(output, "%s=%d\n", table, counts[table])
	}
	fmt.Fprintf(output, "%s=verified\n", action)
	return nil
}

func readBoundedSecret(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximumURLFileBytes+1))
	if err != nil || len(contents) > maximumURLFileBytes {
		return "", errors.New("invalid secret file")
	}
	value := strings.TrimSpace(string(contents))
	if value == "" {
		return "", errors.New("empty secret file")
	}
	return value, nil
}

func openReadOnlySQLite(path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("source is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("source must be a regular file")
	}
	dsn := "file:" + filepath.ToSlash(absolute) + "?mode=ro"
	source, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	source.SetMaxOpenConns(1)
	if err := source.Ping(); err != nil {
		source.Close()
		return nil, err
	}
	if _, err := source.Exec("PRAGMA query_only=ON"); err != nil {
		source.Close()
		return nil, err
	}
	return source, nil
}
