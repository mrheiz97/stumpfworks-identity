package config

import (
	"os"
	"path/filepath"
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
