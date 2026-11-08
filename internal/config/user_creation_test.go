package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserCreatorRoleDefaultsAndExplicitConfig(t *testing.T) {
	if Default().DirectoryUserCreatorGroup != "" || Default().DirectoryUserCreatorGroupGUID != "" {
		t.Fatal("role enabled by default")
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	text := "directory:\n  url: ldaps://dc.example.test:636\n  base_dn: DC=example,DC=test\n  ca_file: fixture-ca.pem\n  user_creator_group_dn: CN=Creators,DC=example,DC=test\n  user_creator_group_guid: " + strings.Repeat("a", 32) + "\n"
	if os.WriteFile(file, []byte(text), 0600) != nil {
		t.Fatal("fixture")
	}
	c, e := Load(file)
	if e != nil || c.DirectoryUserCreatorGroupGUID != strings.Repeat("a", 32) {
		t.Fatal("explicit config", e)
	}
	t.Setenv("SWBADGE_DIRECTORY_USER_CREATOR_GROUP_GUID", strings.Repeat("b", 32))
	c, e = Load(file)
	if e != nil || c.DirectoryUserCreatorGroupGUID != strings.Repeat("b", 32) {
		t.Fatal("env binding", e)
	}
	t.Setenv("SWBADGE_DIRECTORY_USER_CREATOR_GROUP_DN", "CN=Admins,DC=example,DC=test")
	t.Setenv("SWBADGE_DIRECTORY_ADMIN_GROUP_DN", "cn=Admins,dc=example,dc=test")
	if _, e = Load(file); e == nil {
		t.Fatal("shared admin/create group")
	}
}
func TestUserCreationTransportRequiresExplicitPins(t *testing.T) {
	c := Default()
	if c.ADUserCreationEnabled {
		t.Fatal("transport enabled by default")
	}
	disabled, e := c.UserCreationTransport()
	if e != nil || disabled.Enabled {
		t.Fatal("default transport")
	}
	volume := filepath.VolumeName(t.TempDir())
	socket := filepath.Join(volume+string(os.PathSeparator), "ipc", "executor.sock")
	c.ADUserCreationEnabled = true
	c.ADUserCreationSocket = socket
	c.ADUserCreationExecutorUID = "0"
	c.ADUserCreationExecutorGID = "0"
	c.ADUserCreationSocketGID = "65534"
	c.DirectoryEnabled = true
	c.DirectoryURL = "ldaps://dc.example.test:636"
	c.BaseDN = "DC=example,DC=test"
	c.DirectoryCAFile = "fixture-ca.pem"
	c.DirectoryUserCreatorGroup = "CN=Creators,DC=example,DC=test"
	c.DirectoryUserCreatorGroupGUID = strings.Repeat("a", 32)
	c.TLSCertFile = "cert.pem"
	c.TLSKeyFile = "key.pem"
	transport, e := c.UserCreationTransport()
	if e != nil || !transport.Enabled || transport.Peer.UID != 0 || transport.Owner.GID != 65534 {
		t.Fatal("explicit transport", e)
	}
	for _, change := range []func(*Config){func(c *Config) { c.ADUserCreationExecutorUID = "" }, func(c *Config) { c.ADUserCreationExecutorGID = "-1" }, func(c *Config) { c.ADUserCreationSocketGID = "4294967296" }, func(c *Config) { c.ADUserCreationSocket = "relative" }, func(c *Config) { c.Demo = true }, func(c *Config) { c.DirectoryEnabled = false }, func(c *Config) { c.TLSCertFile = "" }, func(c *Config) { c.DirectoryUserCreatorGroupGUID = "" }} {
		candidate := c
		change(&candidate)
		if _, e = candidate.UserCreationTransport(); e == nil {
			t.Fatal("unsafe transport config")
		}
	}
	t.Setenv("SWBADGE_AD_USER_CREATION_ENABLED", "typo")
	if _, e = Load(""); e == nil {
		t.Fatal("ambiguous opt-in")
	}
}
