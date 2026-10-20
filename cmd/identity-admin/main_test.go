package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/jackc/pgx/v5"
	frameworkpg "github.com/mrheiz97/stumpfworks-framework/data/postgres"
	"golang.org/x/crypto/bcrypt"
)

func TestSQLiteOIDCAdministrationCommands(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "identity.db")
	configPath := filepath.Join(directory, "config.yaml")
	configuration := "database:\n  backend: sqlite\n  path: \"" + filepath.ToSlash(databasePath) + "\"\n"
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--config", configPath}
	var created strings.Builder
	if err := execute(append(base, "oidc-client", "create", "--client-id", "fixture-app", "--redirect-uri", "https://app.example.test/callback", "--scopes", "openid profile"), &created); err != nil {
		t.Fatal(err)
	}
	firstSecret := outputValue(t, created.String(), "client_secret")
	store, err := database.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.OIDCClientByID(t.Context(), "fixture-app")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(firstSecret)) != nil {
		store.Close()
		t.Fatal("created client secret was not stored as the matching hash")
	}
	user, err := store.CreateUser(t.Context(), "fixture-user", "Fixture User", "")
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	var rotated strings.Builder
	if err := execute(append(base, "oidc-client", "rotate-secret", "--client-id", "fixture-app"), &rotated); err != nil {
		t.Fatal(err)
	}
	secondSecret := outputValue(t, rotated.String(), "client_secret")
	if firstSecret == secondSecret {
		t.Fatal("secret rotation repeated the prior secret")
	}
	for _, action := range []string{"disable", "enable"} {
		var output strings.Builder
		if err := execute(append(base, "oidc-client", action, "--client-id", "fixture-app"), &output); err != nil {
			t.Fatal(err)
		}
	}
	var subjectOutput strings.Builder
	if err := execute(append(base, "oidc-subject", "--login", user.Username), &subjectOutput); err != nil {
		t.Fatal(err)
	}
	firstSubject := outputValue(t, subjectOutput.String(), "oidc_subject")
	subjectOutput.Reset()
	if err := execute(append(base, "oidc-subject", "--login", user.Username), &subjectOutput); err != nil {
		t.Fatal(err)
	}
	if secondSubject := outputValue(t, subjectOutput.String(), "oidc_subject"); firstSubject == "" || secondSubject != firstSubject {
		t.Fatal("OIDC subject command did not preserve the stable subject")
	}

	store, err = database.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	client, err = store.OIDCClientByID(t.Context(), "fixture-app")
	if err != nil || !client.Enabled || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secondSecret)) != nil || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(firstSecret)) == nil {
		t.Fatal("client administration commands left an invalid final state")
	}
	events, err := store.Audits(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"oidc_client_created": 1, "oidc_client_secret_rotated": 1, "oidc_client_disabled": 1, "oidc_client_enabled": 1, "oidc_subject_created": 1}
	for _, event := range events {
		if _, ok := want[event.EventType]; ok {
			want[event.EventType]--
			if strings.Contains(event.Details, firstSecret) || strings.Contains(event.Details, secondSecret) {
				t.Fatal("audit exposed client secret")
			}
		}
	}
	for event, remaining := range want {
		if remaining != 0 {
			t.Fatalf("audit event %s count mismatch", event)
		}
	}
}

func TestInvalidClientCommandProducesNoSecretOrMutation(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var output strings.Builder
	err = clientCommand(t.Context(), store, []string{"create", "--client-id", "fixture", "--redirect-uri", "http://insecure.example.test/callback"}, &output)
	if err == nil || output.Len() != 0 {
		t.Fatal("invalid client registration returned output")
	}
	if _, err := store.OIDCClientByID(t.Context(), "fixture"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("invalid client registration mutated the store")
	}
}

func TestPostgresOIDCAdministrationCommands(t *testing.T) {
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
	schema := fmt.Sprintf("identity_admin_cli_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := frameworkpg.Open(ctx, frameworkpg.Options{URL: parsed.String(), MaxConnections: 4, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 1 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.MigratePostgres(ctx, pool); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	pool.Close()
	directory := t.TempDir()
	urlPath := filepath.Join(directory, "postgres-url")
	if err := os.WriteFile(urlPath, []byte(parsed.String()), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.yaml")
	configuration := "database:\n  backend: postgres\n  url_file: \"" + filepath.ToSlash(urlPath) + "\"\n  allow_insecure: true\n"
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--config", configPath, "oidc-client"}
	var created strings.Builder
	if err := execute(append(base, "create", "--client-id", "postgres-app", "--redirect-uri", "https://app.example.test/callback", "--scopes", "openid"), &created); err != nil {
		t.Fatal(err)
	}
	firstSecret := outputValue(t, created.String(), "client_secret")
	var rotated strings.Builder
	if err := execute(append(base, "rotate-secret", "--client-id", "postgres-app"), &rotated); err != nil {
		t.Fatal(err)
	}
	secondSecret := outputValue(t, rotated.String(), "client_secret")
	if firstSecret == secondSecret {
		t.Fatal("PostgreSQL CLI rotation repeated the prior secret")
	}
	for _, action := range []string{"disable", "enable"} {
		if err := execute(append(base, action, "--client-id", "postgres-app"), &strings.Builder{}); err != nil {
			t.Fatal(err)
		}
	}
	var storedHash string
	var enabled bool
	if err := admin.QueryRow(ctx, "SELECT secret_hash,enabled FROM "+identifier+".oidc_clients WHERE client_id='postgres-app'").Scan(&storedHash, &enabled); err != nil || !enabled {
		t.Fatal("PostgreSQL CLI left an invalid client state")
	}
	if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(secondSecret)) != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(firstSecret)) == nil {
		t.Fatal("PostgreSQL CLI did not replace the stored secret hash")
	}
	var auditCount int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+identifier+".audit_log WHERE event_type IN ('oidc_client_created','oidc_client_secret_rotated','oidc_client_disabled','oidc_client_enabled') AND details='' AND client_id='postgres-app'").Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatal("PostgreSQL CLI audit contract failed")
	}
}

func outputValue(t *testing.T, output, key string) string {
	t.Helper()
	prefix := key + "="
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			value := strings.TrimPrefix(line, prefix)
			if value == "" {
				t.Fatal("empty command output value")
			}
			return value
		}
	}
	t.Fatal("command output value missing")
	return ""
}
