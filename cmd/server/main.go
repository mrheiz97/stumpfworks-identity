package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	frameworkpg "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	frameworkldap "github.com/TheRealHZL/stumpfworks-framework/directory/ldap"
	frameworkmetrics "github.com/TheRealHZL/stumpfworks-framework/web/metrics"
	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/config"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
	oidcprovider "github.com/TheRealHZL/stumpfworks-identity/internal/oidc"
	app "github.com/TheRealHZL/stumpfworks-identity/internal/server"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	cfgPath := flag.String("config", "", "YAML configuration file")
	show := flag.Bool("version", false, "show version")
	checkDirectory := flag.Bool("check-directory", false, "verify configured directory connection and exit")
	registerClient := flag.String("register-client", "", "provision a client ID and print its token once")
	rotateClient := flag.String("rotate-client-token", "", "replace a client's status token and print the new token once")
	disableClient := flag.String("disable-client", "", "disable a client's status credential")
	enableClient := flag.String("enable-client", "", "enable a client's status credential")
	flag.Parse()
	if *show {
		fmt.Println("sw-badge-server", version.Version)
		return
	}
	cfg, e := config.Load(*cfgPath)
	if e != nil {
		slog.Error("configuration failed", "error", e)
		os.Exit(1)
	}
	configuredDirectory := directory.LDAP{URL: cfg.DirectoryURL, BaseDN: cfg.BaseDN, BindDN: cfg.BindDN, BindPassword: cfg.BindPassword, Domain: cfg.DirectoryDomain, AdminGroupDN: cfg.DirectoryAdminGroup, CAFile: cfg.DirectoryCAFile, CertSHA256: cfg.DirectoryCertSHA256}
	metricsRegistry := frameworkmetrics.New()
	var directoryObserver frameworkldap.Observer
	if cfg.MetricsEnabled {
		directoryObserver = metricsRegistry.LDAPObserver()
	}
	runtimeDirectory, e := runtimeDirectoryForConfig(cfg, configuredDirectory, directoryObserver)
	if e != nil {
		slog.Error("framework directory read configuration failed", "error", e)
		os.Exit(1)
	}
	if *checkDirectory {
		if !cfg.DirectoryEnabled {
			slog.Error("directory is disabled")
			os.Exit(1)
		}
		users, err := configuredDirectory.ListUsers(context.Background())
		if err != nil {
			slog.Error("directory check failed", "error", err)
			os.Exit(1)
		}
		fmt.Printf("directory ok: %d active users\n", len(users))
		return
	}
	st, closeDatabase, e := runtimeStoreForConfig(context.Background(), cfg)
	if e != nil {
		slog.Error("database failed", "error", e)
		os.Exit(1)
	}
	defer closeDatabase()
	clientActions := 0
	for _, value := range []string{*registerClient, *rotateClient, *disableClient, *enableClient} {
		if value != "" {
			clientActions++
		}
	}
	if clientActions > 1 {
		slog.Error("select only one client management action")
		os.Exit(1)
	}
	clientID := *registerClient
	if clientID == "" {
		clientID = *rotateClient
	}
	if clientID == "" {
		clientID = *disableClient
	}
	if clientID == "" {
		clientID = *enableClient
	}
	if clientID != "" {
		valid := len(clientID) > 0 && len(clientID) <= 64
		for _, r := range clientID {
			if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				valid = false
			}
		}
		if !valid {
			slog.Error("client ID must contain only letters, digits, dot, dash, or underscore")
			os.Exit(1)
		}
		if *disableClient != "" || *enableClient != "" {
			enabled := *enableClient != ""
			if err := st.SetClientEnabled(context.Background(), clientID, enabled); err != nil {
				slog.Error("client state change failed", "error", err)
				os.Exit(1)
			}
			fmt.Printf("client_id=%s\nenabled=%t\n", clientID, enabled)
			return
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			slog.Error("client token generation failed", "error", err)
			os.Exit(1)
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		if *registerClient != "" {
			if _, err := st.CreateClient(context.Background(), clientID, app.HashClientToken(token)); err != nil {
				slog.Error("client registration failed", "error", err)
				os.Exit(1)
			}
		} else {
			if err := st.RotateClientToken(context.Background(), clientID, app.HashClientToken(token)); err != nil {
				slog.Error("client token rotation failed", "error", err)
				os.Exit(1)
			}
		}
		fmt.Printf("client_id=%s\ntoken=%s\n", clientID, token)
		return
	}
	if cfg.Demo {
		seed(st)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var srv *app.Server
	var sessions *adminauth.Sessions
	if cfg.DirectoryEnabled {
		if !strings.HasPrefix(cfg.DirectoryURL, "ldaps://") {
			slog.Error("directory URL must use ldaps:// when enabled")
			os.Exit(1)
		}
		sessions, e = adminauth.NewSessions(cfg.SessionSecret, time.Hour)
		if e != nil {
			slog.Error("session configuration failed", "error", e)
			os.Exit(1)
		}
		srv = app.NewProtected(st, log, runtimeDirectory, sessions)
	} else {
		srv = app.New(st, log)
	}
	if err := srv.ConfigureClientTargetVersion(cfg.ClientTargetVersion); err != nil {
		slog.Error("client target version configuration failed", "error", err)
		os.Exit(1)
	}
	if cfg.PKINITEnabled {
		issuer, err := app.LoadPKINITIssuer(cfg.PKINITCACertFile, cfg.PKINITCAKeyFile, cfg.PKINITRealm, 10*time.Minute)
		if err != nil {
			slog.Error("PKINIT configuration failed", "error", err)
			os.Exit(1)
		}
		srv.ConfigurePKINIT(issuer)
	}
	if cfg.OIDCEnabled {
		if !cfg.DirectoryEnabled {
			slog.Error("OIDC requires the protected directory authentication mode")
			os.Exit(1)
		}
		provider, err := oidcprovider.New(cfg.OIDCIssuer, strings.Split(cfg.OIDCSigningKeyFiles, ","), st, runtimeDirectory, sessions)
		if err != nil {
			slog.Error("OIDC configuration failed", "error", err)
			os.Exit(1)
		}
		srv.ConfigureOIDC(provider)
	}
	applicationHandler := srv.Handler()
	if cfg.MetricsEnabled {
		applicationHandler, e = applicationHandlerWithMetrics(applicationHandler, cfg.MetricsToken, metricsRegistry)
		if e != nil {
			slog.Error("metrics configuration failed", "error", e)
			os.Exit(1)
		}
	}
	log.Info("server starting", "component", "server", "listen", cfg.Listen, "version", version.Version, "metrics_enabled", cfg.MetricsEnabled)
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			slog.Error("both TLS certificate and key are required")
			os.Exit(1)
		}
		e = http.ListenAndServeTLS(cfg.Listen, cfg.TLSCertFile, cfg.TLSKeyFile, applicationHandler)
	} else {
		e = http.ListenAndServe(cfg.Listen, applicationHandler)
	}
	if e != nil {
		slog.Error("server stopped", "error", e)
		os.Exit(1)
	}
}

func applicationHandlerWithMetrics(application http.Handler, token string, registry *frameworkmetrics.Registry) (http.Handler, error) {
	if application == nil || registry == nil {
		return nil, fmt.Errorf("metrics requires application handler and registry")
	}
	metricsHandler, err := frameworkmetrics.ProtectBearer(registry.Handler(), token)
	if err != nil {
		return nil, err
	}
	root := http.NewServeMux()
	root.Handle("GET /metrics", metricsHandler)
	root.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	root.Handle("/", registry.Middleware(application))
	return root, nil
}

func runtimeDirectoryForConfig(cfg config.Config, existing directory.LDAP, observer frameworkldap.Observer) (directory.Directory, error) {
	if !cfg.DirectoryFrameworkReadEnabled {
		return existing, nil
	}
	if !cfg.DirectoryEnabled {
		return nil, fmt.Errorf("framework directory reads require directory.enabled")
	}
	return existing.WithFrameworkLookupsObserved(observer)
}

func runtimeStoreForConfig(ctx context.Context, cfg config.Config) (database.ApplicationStore, func(), error) {
	switch cfg.DatabaseBackend {
	case "", "sqlite":
		store, err := database.Open(cfg.DatabasePath)
		if err != nil {
			return nil, func() {}, err
		}
		return store, func() { _ = store.Close() }, nil
	case "postgres":
		if cfg.DatabaseURL == "" {
			return nil, func() {}, fmt.Errorf("PostgreSQL backend requires SWBADGE_POSTGRES_URL or database.url_file")
		}
		openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		pool, err := frameworkpg.Open(openCtx, frameworkpg.Options{URL: cfg.DatabaseURL, MaxConnections: 10, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 16 << 20, AllowInsecure: cfg.DatabaseAllowInsecure})
		if err != nil {
			return nil, func() {}, fmt.Errorf("open PostgreSQL runtime pool failed")
		}
		store, err := database.NewPostgresStore(pool)
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
		return nil, func() {}, fmt.Errorf("unsupported database backend %q", cfg.DatabaseBackend)
	}
}

func seed(s database.ApplicationStore) {
	for _, u := range []struct{ n, d string }{{"alice", "Alice Example"}, {"bob", "Bob Example"}} {
		_, _ = s.CreateUser(context.Background(), u.n, u.d, "")
	}
}
