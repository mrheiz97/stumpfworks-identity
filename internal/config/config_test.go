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

func TestClientAPIIsSeparatelyOptInAndEnvironmentOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "client_api:\n  enabled: false\n  listen: 127.0.0.1:8444\n  ca_file: /secure/device-ca.pem\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.ClientAPIEnabled || loaded.ClientAPIListen != "127.0.0.1:8444" || loaded.ClientAPICAFile != "/secure/device-ca.pem" {
		t.Fatalf("unexpected client API config: %+v %v", loaded, err)
	}
	t.Setenv("SWBADGE_CLIENT_API_ENABLED", "true")
	t.Setenv("SWBADGE_CLIENT_API_LISTEN", "127.0.0.1:9444")
	t.Setenv("SWBADGE_CLIENT_API_CA_FILE", "/override/device-ca.pem")
	loaded, err = Load(path)
	if err != nil || !loaded.ClientAPIEnabled || loaded.ClientAPIListen != "127.0.0.1:9444" || loaded.ClientAPICAFile != "/override/device-ca.pem" {
		t.Fatalf("client API environment override failed: %+v %v", loaded, err)
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

func TestPasskeysAreOptInAndEnvironmentOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("passkeys:\n  enabled: false\n  rp_id: login.example.test\n  origin: https://login.example.test:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.PasskeysEnabled || loaded.PasskeyRPID != "login.example.test" || loaded.PasskeyOrigin != "https://login.example.test:8080" {
		t.Fatalf("unexpected Passkey config: %+v %v", loaded, err)
	}
	t.Setenv("SWBADGE_PASSKEYS_ENABLED", "true")
	t.Setenv("SWBADGE_PASSKEY_RP_ID", "identity.example.test")
	loaded, err = Load(path)
	if err != nil || !loaded.PasskeysEnabled || loaded.PasskeyRPID != "identity.example.test" {
		t.Fatalf("Passkey environment override failed: %+v %v", loaded, err)
	}
}

func TestEmergencyAdministratorIsOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("emergency_admin:\n  enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.EmergencyAdminEnabled {
		t.Fatalf("unsafe emergency default: %+v %v", loaded, err)
	}
	t.Setenv("SWBADGE_EMERGENCY_ADMIN_ENABLED", "true")
	loaded, err = Load(path)
	if err != nil || !loaded.EmergencyAdminEnabled {
		t.Fatalf("emergency opt-in failed: %+v %v", loaded, err)
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

func TestAdministrativeRoleGroupsAreOptionalAndEnvironmentOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "directory:\n  admin_group_dn: CN=Admins,DC=example,DC=test\n  identity_operator_group_dn: CN=Identity Operators,DC=example,DC=test\n  oidc_operator_group_dn: CN=OIDC Operators,DC=example,DC=test\n  client_operator_group_dn: CN=Client Operators,DC=example,DC=test\n  identity_auditor_group_dn: CN=Auditors,DC=example,DC=test\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.DirectoryIdentityOperatorGroup == "" || loaded.DirectoryOIDCOperatorGroup == "" || loaded.DirectoryClientOperatorGroup == "" || loaded.DirectoryAuditorGroup == "" {
		t.Fatalf("role groups not loaded: %+v %v", loaded, err)
	}
	t.Setenv("SWBADGE_DIRECTORY_IDENTITY_AUDITOR_GROUP_DN", "CN=Security Reviewers,DC=example,DC=test")
	loaded, err = Load(path)
	if err != nil || loaded.DirectoryAuditorGroup != "CN=Security Reviewers,DC=example,DC=test" {
		t.Fatalf("role group environment override failed: %+v %v", loaded, err)
	}
}

func TestIndentedEmptyValueDoesNotChangeSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "directory:\n  enabled: true\n  cert_sha256:\n  identity_auditor_group_dn: CN=Auditors,DC=example,DC=test\noidc:\n  signing_key_files:\n  issuer: https://identity.example.test\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DirectoryCertSHA256 != "" {
		t.Fatalf("empty certificate pin was not preserved: %q", loaded.DirectoryCertSHA256)
	}
	if loaded.DirectoryAuditorGroup != "CN=Auditors,DC=example,DC=test" {
		t.Fatalf("key after empty value left directory section: %q", loaded.DirectoryAuditorGroup)
	}
	if loaded.OIDCSigningKeyFiles != "" || loaded.OIDCIssuer != "https://identity.example.test" {
		t.Fatalf("empty OIDC value changed section: keys=%q issuer=%q", loaded.OIDCSigningKeyFiles, loaded.OIDCIssuer)
	}
}

func TestAdministrativeRoleGroupsMustBeDistinct(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "directory:\n  admin_group_dn: CN=Admins,DC=example,DC=test\n  oidc_operator_group_dn: cn=admins,dc=example,dc=test\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("duplicate role group accepted: %v", err)
	}
}

func TestMetricsAreOptInAndTokenComesFromProtectedInputs(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "metrics-token")
	if err := os.WriteFile(secretFile, []byte("synthetic-metrics-token-at-least-32-bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "metrics:\n  enabled: true\n  token_file: \"" + secretFile + "\"\n  backup_path: /protected/latest.db\n  maintenance_file: /run/identity-maintenance\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || !loaded.MetricsEnabled || loaded.MetricsToken != "synthetic-metrics-token-at-least-32-bytes" {
		t.Fatalf("metrics secret file was not loaded: enabled=%t token_length=%d err=%v", loaded.MetricsEnabled, len(loaded.MetricsToken), err)
	}
	if loaded.MetricsBackupPath != "/protected/latest.db" || loaded.MetricsMaintenanceFile != "/run/identity-maintenance" {
		t.Fatalf("metrics operational paths not loaded: %+v", loaded)
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
