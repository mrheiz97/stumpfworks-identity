package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	frameworkpg "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	frameworkmetrics "github.com/TheRealHZL/stumpfworks-framework/web/metrics"
	"github.com/TheRealHZL/stumpfworks-identity/internal/config"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
	"github.com/jackc/pgx/v5"
)

func TestFrameworkDirectoryRuntimeSelectionIsExplicitAndFailClosed(t *testing.T) {
	base := directory.LDAP{URL: "ldaps://directory.example.test", BaseDN: "DC=example,DC=test", BindDN: "CN=service,DC=example,DC=test", BindPassword: "synthetic"}
	got, err := runtimeDirectoryForConfig(config.Config{}, base, nil)
	if err != nil || got.(directory.LDAP) != base {
		t.Fatal("default path changed the existing directory")
	}

	enabled := config.Config{DirectoryFrameworkReadEnabled: true}
	if _, err := runtimeDirectoryForConfig(enabled, base, nil); err == nil {
		t.Fatal("framework reads accepted while directory disabled")
	}

	enabled.DirectoryEnabled = true
	pinned := base
	pinned.CertSHA256 = "legacy-pin"
	if _, err := runtimeDirectoryForConfig(enabled, pinned, nil); err == nil {
		t.Fatal("legacy SAN-bypass pin accepted")
	}
	if got, err := runtimeDirectoryForConfig(enabled, base, nil); err != nil || got == nil {
		t.Fatalf("valid framework read configuration rejected: %v", err)
	}
}

func TestApplicationMetricsEndpointIsExplicitlyProtected(t *testing.T) {
	const token = "synthetic-identity-metrics-token-32-bytes"
	application := http.NewServeMux()
	application.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler, err := applicationHandlerWithMetrics(application, token, frameworkmetrics.New())
	if err != nil {
		t.Fatal(err)
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized || strings.Contains(unauthorized.Body.String(), token) {
		t.Fatal("metrics endpoint was not safely protected")
	}

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusNoContent {
		t.Fatal("application handler changed")
	}

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK || !strings.Contains(authorized.Body.String(), "swf_http_requests_total") || strings.Contains(authorized.Body.String(), token) {
		t.Fatal("authorized metrics exposition invalid")
	}
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != http.MethodGet {
		t.Fatal("non-GET metrics request reached application")
	}
	if _, err := applicationHandlerWithMetrics(nil, token, frameworkmetrics.New()); err == nil {
		t.Fatal("nil application accepted")
	}
	if _, err := applicationHandlerWithMetrics(application, token, nil); err == nil {
		t.Fatal("nil registry accepted")
	}
}

func TestRuntimeStoreSelectionDefaultsToSQLiteAndFailsClosed(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = t.TempDir() + "/identity.db"
	store, closeStore, err := runtimeStoreForConfig(t.Context(), cfg)
	if err != nil || store == nil {
		t.Fatalf("default SQLite backend failed: %v", err)
	}
	closeStore()

	if _, closeInvalid, err := runtimeStoreForConfig(t.Context(), config.Config{DatabaseBackend: "unknown"}); err == nil {
		closeInvalid()
		t.Fatal("unknown database backend accepted")
	}
	if _, closeMissing, err := runtimeStoreForConfig(t.Context(), config.Config{DatabaseBackend: "postgres"}); err == nil {
		closeMissing()
		t.Fatal("PostgreSQL backend accepted without runtime URL")
	}
}

func TestPostgresRuntimeUsesPreMigratedSchemaAndNeverCreatesIt(t *testing.T) {
	dsn := os.Getenv("IDENTITY_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL cluster not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Port() != "55441" || u.Path != "/postgres" {
		t.Fatal("runtime test requires disposable loopback PostgreSQL on port 55441")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("disposable PostgreSQL unavailable")
	}
	defer admin.Close(context.Background())

	schema := fmt.Sprintf("identity_runtime_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()

	if _, closeMissing, err := runtimeStoreForConfig(ctx, config.Config{DatabaseBackend: "postgres", DatabaseURL: u.String(), DatabaseAllowInsecure: true}); err == nil {
		closeMissing()
		t.Fatal("runtime startup created or accepted an unmigrated schema")
	}
	migrationPool, err := frameworkpg.Open(ctx, frameworkpg.Options{URL: u.String(), MaxConnections: 2, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 1 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.MigratePostgres(ctx, migrationPool); err != nil {
		migrationPool.Close()
		t.Fatal(err)
	}
	migrationPool.Close()

	store, closeStore, err := runtimeStoreForConfig(ctx, config.Config{DatabaseBackend: "postgres", DatabaseURL: u.String(), DatabaseAllowInsecure: true})
	if err != nil {
		t.Fatalf("pre-migrated PostgreSQL runtime rejected: %v", err)
	}
	defer closeStore()
	created, err := store.CreateUser(ctx, "runtime-user", "Runtime User", "")
	if err != nil || created.ID == 0 {
		t.Fatalf("PostgreSQL runtime write failed: %v", err)
	}
	counts, err := store.Counts(ctx)
	if err != nil || counts["users"] != 1 {
		t.Fatalf("PostgreSQL runtime read failed: counts=%v err=%v", counts, err)
	}
}
