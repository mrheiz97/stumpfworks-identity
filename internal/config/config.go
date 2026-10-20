package config

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

type Config struct {
	Listen, TLSCertFile, TLSKeyFile, DatabaseBackend, DatabasePath, DatabaseURL, DatabaseURLFile string
	DirectoryURL, BaseDN, BindDN, BindPassword                                                   string
	DirectoryDomain, DirectoryAdminGroup, DirectoryCAFile                                        string
	DirectoryBindPasswordFile, DirectoryCertSHA256                                               string
	SessionSecret                                                                                string
	SessionSecretFile                                                                            string
	MetricsToken, MetricsTokenFile                                                               string
	PKINITCACertFile, PKINITCAKeyFile, PKINITRealm                                               string
	ClientTargetVersion                                                                          string
	OIDCIssuer, OIDCSigningKeyFiles                                                              string
	DirectoryEnabled, DirectoryFrameworkReadEnabled, MetricsEnabled, PKINITEnabled, OIDCEnabled  bool
	DatabaseAllowInsecure, Demo                                                                  bool
}

func Default() Config {
	return Config{Listen: "0.0.0.0:8080", DatabaseBackend: "sqlite", DatabasePath: "./data/badges.db"}
}

// Load supports the deliberately small YAML surface used by this project. Environment variables override it.
func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, err
		}
		defer f.Close()
		section := ""
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
			if line == "" {
				continue
			}
			if strings.HasSuffix(line, ":") {
				section = strings.TrimSuffix(line, ":")
				continue
			}
			p := strings.SplitN(line, ":", 2)
			if len(p) != 2 {
				continue
			}
			key, val := section+"."+strings.TrimSpace(p[0]), strings.Trim(strings.TrimSpace(p[1]), `"'`)
			switch key {
			case "server.listen":
				c.Listen = val
			case "server.tls_cert_file":
				c.TLSCertFile = val
			case "server.tls_key_file":
				c.TLSKeyFile = val
			case "database.path":
				c.DatabasePath = val
			case "database.backend":
				c.DatabaseBackend = val
			case "database.url_file":
				c.DatabaseURLFile = val
			case "database.allow_insecure":
				c.DatabaseAllowInsecure = val == "true"
			case "directory.enabled":
				c.DirectoryEnabled = val == "true"
			case "directory.framework_read_enabled":
				c.DirectoryFrameworkReadEnabled = val == "true"
			case "directory.url":
				c.DirectoryURL = val
			case "directory.base_dn":
				c.BaseDN = val
			case "directory.bind_dn":
				c.BindDN = val
			case "directory.bind_password":
				c.BindPassword = val
			case "directory.domain":
				c.DirectoryDomain = val
			case "directory.admin_group_dn":
				c.DirectoryAdminGroup = val
			case "directory.ca_file":
				c.DirectoryCAFile = val
			case "directory.bind_password_file":
				c.DirectoryBindPasswordFile = val
			case "directory.cert_sha256":
				c.DirectoryCertSHA256 = val
			case "auth.session_secret":
				c.SessionSecret = val
			case "auth.session_secret_file":
				c.SessionSecretFile = val
			case "metrics.enabled":
				c.MetricsEnabled = val == "true"
			case "metrics.token_file":
				c.MetricsTokenFile = val
			case "pkinit.enabled":
				c.PKINITEnabled = val == "true"
			case "pkinit.ca_cert_file":
				c.PKINITCACertFile = val
			case "pkinit.ca_key_file":
				c.PKINITCAKeyFile = val
			case "pkinit.realm":
				c.PKINITRealm = val
			case "updates.client_target_version":
				c.ClientTargetVersion = val
			case "oidc.enabled":
				c.OIDCEnabled = val == "true"
			case "oidc.issuer":
				c.OIDCIssuer = val
			case "oidc.signing_key_files":
				c.OIDCSigningKeyFiles = val
			}
		}
		if err := s.Err(); err != nil {
			return c, err
		}
	}
	set := func(k string, dst *string) {
		if v, ok := os.LookupEnv(k); ok {
			*dst = v
		}
	}
	set("SWBADGE_LISTEN", &c.Listen)
	set("SWBADGE_TLS_CERT_FILE", &c.TLSCertFile)
	set("SWBADGE_TLS_KEY_FILE", &c.TLSKeyFile)
	set("SWBADGE_DATABASE_PATH", &c.DatabasePath)
	set("SWBADGE_DATABASE_BACKEND", &c.DatabaseBackend)
	set("SWBADGE_POSTGRES_URL", &c.DatabaseURL)
	set("SWBADGE_POSTGRES_URL_FILE", &c.DatabaseURLFile)
	set("SWBADGE_DIRECTORY_URL", &c.DirectoryURL)
	set("SWBADGE_DIRECTORY_BASE_DN", &c.BaseDN)
	set("SWBADGE_DIRECTORY_BIND_DN", &c.BindDN)
	set("SWBADGE_DIRECTORY_BIND_PASSWORD", &c.BindPassword)
	set("SWBADGE_DIRECTORY_DOMAIN", &c.DirectoryDomain)
	set("SWBADGE_DIRECTORY_ADMIN_GROUP_DN", &c.DirectoryAdminGroup)
	set("SWBADGE_DIRECTORY_CA_FILE", &c.DirectoryCAFile)
	set("SWBADGE_DIRECTORY_BIND_PASSWORD_FILE", &c.DirectoryBindPasswordFile)
	set("SWBADGE_DIRECTORY_CERT_SHA256", &c.DirectoryCertSHA256)
	set("SWBADGE_SESSION_SECRET", &c.SessionSecret)
	set("SWBADGE_SESSION_SECRET_FILE", &c.SessionSecretFile)
	set("SWBADGE_METRICS_TOKEN", &c.MetricsToken)
	set("SWBADGE_METRICS_TOKEN_FILE", &c.MetricsTokenFile)
	set("SWBADGE_PKINIT_CA_CERT_FILE", &c.PKINITCACertFile)
	set("SWBADGE_PKINIT_CA_KEY_FILE", &c.PKINITCAKeyFile)
	set("SWBADGE_PKINIT_REALM", &c.PKINITRealm)
	set("SWBADGE_CLIENT_TARGET_VERSION", &c.ClientTargetVersion)
	set("SWBADGE_OIDC_ISSUER", &c.OIDCIssuer)
	set("SWBADGE_OIDC_SIGNING_KEY_FILES", &c.OIDCSigningKeyFiles)
	if v, ok := os.LookupEnv("SWBADGE_DIRECTORY_ENABLED"); ok {
		c.DirectoryEnabled = v == "true"
	}
	if v, ok := os.LookupEnv("SWBADGE_DIRECTORY_FRAMEWORK_READ_ENABLED"); ok {
		c.DirectoryFrameworkReadEnabled = v == "true"
	}
	if v, ok := os.LookupEnv("SWBADGE_PKINIT_ENABLED"); ok {
		c.PKINITEnabled = v == "true"
	}
	if v, ok := os.LookupEnv("SWBADGE_METRICS_ENABLED"); ok {
		c.MetricsEnabled = v == "true"
	}
	if v, ok := os.LookupEnv("SWBADGE_OIDC_ENABLED"); ok {
		c.OIDCEnabled = v == "true"
	}
	if v, ok := os.LookupEnv("SWBADGE_POSTGRES_ALLOW_INSECURE"); ok {
		c.DatabaseAllowInsecure = v == "true"
	}
	c.Demo = os.Getenv("SWBADGE_DEMO") == "true"
	readSecret := func(path string, dst *string) error {
		if path == "" || *dst != "" {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		const maxSecretBytes = 64 << 10
		b, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
		if err != nil {
			return err
		}
		if len(b) > maxSecretBytes {
			return errors.New("secret file exceeds 64 KiB limit")
		}
		*dst = strings.TrimSpace(string(b))
		return nil
	}
	if err := readSecret(c.DirectoryBindPasswordFile, &c.BindPassword); err != nil {
		return c, err
	}
	if err := readSecret(c.SessionSecretFile, &c.SessionSecret); err != nil {
		return c, err
	}
	if c.MetricsEnabled {
		if err := readSecret(c.MetricsTokenFile, &c.MetricsToken); err != nil {
			return c, err
		}
	}
	if c.DatabaseBackend == "postgres" {
		if err := readSecret(c.DatabaseURLFile, &c.DatabaseURL); err != nil {
			return c, err
		}
	}
	return c, nil
}
