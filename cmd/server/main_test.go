package main

import (
	"testing"

	"github.com/TheRealHZL/stumpfworks-identity/internal/config"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
)

func TestFrameworkDirectoryRuntimeSelectionIsExplicitAndFailClosed(t *testing.T) {
	base := directory.LDAP{URL: "ldaps://directory.example.test", BaseDN: "DC=example,DC=test", BindDN: "CN=service,DC=example,DC=test", BindPassword: "synthetic"}
	got, err := runtimeDirectoryForConfig(config.Config{}, base)
	if err != nil || got.(directory.LDAP) != base {
		t.Fatal("default path changed the existing directory")
	}

	enabled := config.Config{DirectoryFrameworkReadEnabled: true}
	if _, err := runtimeDirectoryForConfig(enabled, base); err == nil {
		t.Fatal("framework reads accepted while directory disabled")
	}

	enabled.DirectoryEnabled = true
	pinned := base
	pinned.CertSHA256 = "legacy-pin"
	if _, err := runtimeDirectoryForConfig(enabled, pinned); err == nil {
		t.Fatal("legacy SAN-bypass pin accepted")
	}
	if got, err := runtimeDirectoryForConfig(enabled, base); err != nil || got == nil {
		t.Fatalf("valid framework read configuration rejected: %v", err)
	}
}
