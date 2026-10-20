package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientTargetVersionConfigAndEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("updates:\n  client_target_version: 1.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.ClientTargetVersion != "1.2.1" {
		t.Fatalf("unexpected config: %+v, %v", loaded, err)
	}
	t.Setenv("SWBADGE_CLIENT_TARGET_VERSION", "1.2.2")
	loaded, err = Load(path)
	if err != nil || loaded.ClientTargetVersion != "1.2.2" {
		t.Fatalf("environment did not override config: %+v, %v", loaded, err)
	}
}

func TestOIDCConfigIsOptInAndEnvironmentOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("oidc:\n  enabled: false\n  issuer: https://identity.example.test\n  signing_key_files: /secure/current.pem,/secure/old.pem\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.OIDCEnabled || loaded.OIDCIssuer != "https://identity.example.test" || loaded.OIDCSigningKeyFiles == "" {
		t.Fatalf("unexpected config: %+v %v", loaded, err)
	}
	t.Setenv("SWBADGE_OIDC_ENABLED", "true")
	t.Setenv("SWBADGE_OIDC_ISSUER", "https://override.example.test")
	loaded, err = Load(path)
	if err != nil || !loaded.OIDCEnabled || loaded.OIDCIssuer != "https://override.example.test" {
		t.Fatalf("environment override failed: %+v %v", loaded, err)
	}
}

func TestFrameworkDirectoryReadsAreSeparatelyOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("directory:\n  enabled: true\n  framework_read_enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || !loaded.DirectoryEnabled || loaded.DirectoryFrameworkReadEnabled {
		t.Fatalf("unexpected opt-in defaults: %+v %v", loaded, err)
	}
	t.Setenv("SWBADGE_DIRECTORY_FRAMEWORK_READ_ENABLED", "true")
	loaded, err = Load(path)
	if err != nil || !loaded.DirectoryFrameworkReadEnabled {
		t.Fatalf("framework read environment opt-in failed: %+v %v", loaded, err)
	}
}

func TestMetricsAreOptInAndTokenComesFromProtectedInputs(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "metrics-token")
	if err := os.WriteFile(secretFile, []byte("synthetic-metrics-token-at-least-32-bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "metrics:\n  enabled: true\n  token_file: \"" + secretFile + "\"\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || !loaded.MetricsEnabled || loaded.MetricsToken != "synthetic-metrics-token-at-least-32-bytes" {
		t.Fatalf("metrics secret file was not loaded: enabled=%t token_length=%d err=%v", loaded.MetricsEnabled, len(loaded.MetricsToken), err)
	}
	t.Setenv("SWBADGE_METRICS_TOKEN", "environment-metrics-token-at-least-32-bytes")
	loaded, err = Load(path)
	if err != nil || loaded.MetricsToken != "environment-metrics-token-at-least-32-bytes" {
		t.Fatal("environment token did not override token file")
	}
}

func TestSecretFilesAreBounded(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "oversized-secret")
	if err := os.WriteFile(secretFile, []byte(strings.Repeat("x", (64<<10)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("metrics:\n  enabled: true\n  token_file: \""+secretFile+"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || strings.Contains(err.Error(), strings.Repeat("x", 32)) {
		t.Fatal("oversized secret file accepted or exposed")
	}
}

func TestDisabledMetricsDoNotRequireSecretFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("metrics:\n  enabled: false\n  token_file: /missing/metrics-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.MetricsEnabled || loaded.MetricsToken != "" {
		t.Fatalf("disabled metrics loaded secret: %+v %v", loaded, err)
	}
}

func TestPostgresRuntimeIsExplicitAndLoadsBoundedURLFile(t *testing.T) {
	if got := Default(); got.DatabaseBackend != "sqlite" || got.DatabaseURL != "" || got.DatabaseAllowInsecure {
		t.Fatalf("unsafe database defaults: %+v", got)
	}
	secretFile := filepath.Join(t.TempDir(), "postgres-url")
	if err := os.WriteFile(secretFile, []byte("postgres://runtime:secret@database.example.test/identity?sslmode=verify-full\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "database:\n  backend: postgres\n  url_file: \"" + secretFile + "\"\n  allow_insecure: false\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.DatabaseBackend != "postgres" || loaded.DatabaseURL == "" || loaded.DatabaseAllowInsecure {
		t.Fatalf("PostgreSQL configuration failed: backend=%q url_set=%t insecure=%t err=%v", loaded.DatabaseBackend, loaded.DatabaseURL != "", loaded.DatabaseAllowInsecure, err)
	}
	t.Setenv("SWBADGE_POSTGRES_URL", "postgres://runtime:override@database.example.test/identity?sslmode=verify-full")
	loaded, err = Load(path)
	if err != nil || !strings.Contains(loaded.DatabaseURL, "override") {
		t.Fatal("PostgreSQL environment URL did not override file")
	}
}
