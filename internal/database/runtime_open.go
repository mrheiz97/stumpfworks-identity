package database

import (
	"context"
	"fmt"
	"time"

	frameworkpg "github.com/mrheiz97/stumpfworks-framework/data/postgres"
)

// RuntimeOptions contains only the database settings needed by executables.
// Schema migrations remain an explicit operational step.
type RuntimeOptions struct {
	Backend                 string
	SQLitePath              string
	PostgreSQLURL           string
	PostgreSQLAllowInsecure bool
}

func OpenRuntime(ctx context.Context, options RuntimeOptions) (ApplicationStore, func(), error) {
	switch options.Backend {
	case "", "sqlite":
		store, err := Open(options.SQLitePath)
		if err != nil {
			return nil, func() {}, err
		}
		return store, func() { _ = store.Close() }, nil
	case "postgres":
		if options.PostgreSQLURL == "" {
			return nil, func() {}, fmt.Errorf("PostgreSQL backend requires a configured database URL")
		}
		openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		pool, err := frameworkpg.Open(openCtx, frameworkpg.Options{
			URL: options.PostgreSQLURL, MaxConnections: 10,
			ConnectTimeout: 5 * time.Second, MaxMessageBytes: 16 << 20,
			AllowInsecure: options.PostgreSQLAllowInsecure,
		})
		if err != nil {
			return nil, func() {}, fmt.Errorf("open PostgreSQL runtime pool failed")
		}
		store, err := NewPostgresStore(pool)
		if err != nil {
			pool.Close()
			return nil, func() {}, err
		}
		if _, err := store.Counts(openCtx); err != nil {
			pool.Close()
			return nil, func() {}, fmt.Errorf("verify pre-migrated PostgreSQL schema and runtime privileges failed")
		}
		return store, pool.Close, nil
	default:
		return nil, func() {}, fmt.Errorf("unsupported database backend %q", options.Backend)
	}
}
