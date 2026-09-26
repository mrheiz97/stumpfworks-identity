package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	frameworkmetrics "github.com/TheRealHZL/stumpfworks-framework/web/metrics"
	"github.com/TheRealHZL/stumpfworks-identity/internal/config"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
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
