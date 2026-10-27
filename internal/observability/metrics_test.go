package observability

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

func TestOperationalFilesExposeOnlyFixedLabels(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsServer.Close()
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "server.crt")
	backupPath := filepath.Join(directory, "private-backup-name.db")
	maintenancePath := filepath.Join(directory, "private-maintenance-name")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	if err := os.WriteFile(certificatePath, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, []byte("enabled"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry := New("test", "sqlite", nil)
	registry.ConfigureOperationalFiles(certificatePath, backupPath, maintenancePath)
	response := httptest.NewRecorder()
	registry.Handler(store).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, expected := range []string{"sw_identity_certificate_not_after_seconds", "sw_identity_backup_timestamp_seconds", "sw_identity_maintenance_mode 1"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q", expected)
		}
	}
	for _, forbidden := range []string{certificatePath, backupPath, maintenancePath, "private-backup-name", "private-maintenance-name"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("operational metrics exposed path %q", forbidden)
		}
	}
}

func TestMetricsAreBoundedAndContainNoIdentityData(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	client, err := store.CreateClient(t.Context(), "private-client-id", "private-token-hash")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateClientStatusWithUpdate(t.Context(), client.ClientID, "private-version", "ok", "ok", "ok", "ok", nil); err != nil {
		t.Fatal(err)
	}

	registry := New("1.2.3", "sqlite", map[string]bool{"directory": true, "oidc": true})
	registry.now = func() time.Time { return time.Now().UTC() }
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/badge", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "denied", http.StatusUnauthorized) })
	handler := registry.Middleware(mux)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/badge", strings.NewReader("private-user private-badge private-ip"))
	handler.ServeHTTP(httptest.NewRecorder(), request)

	response := httptest.NewRecorder()
	registry.Handler(store).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, expected := range []string{
		`sw_identity_info{version="1.2.3",backend="sqlite"} 1`,
		`sw_identity_module_enabled{module="directory"} 1`,
		`sw_identity_operations_total{component="badge",outcome="denied"} 1`,
		`sw_identity_clients{state="fresh"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q in metrics", expected)
		}
	}
	for _, forbidden := range []string{"private-user", "private-badge", "private-client-id", "private-token-hash", "private-version", "private-ip"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics exposed %q", forbidden)
		}
	}
}

func TestDisabledClientsHaveOneExclusiveOperationalState(t *testing.T) {
	now := time.Date(2026, 10, 27, 17, 0, 0, 0, time.UTC)
	old := now.Add(-24 * time.Hour)
	response := httptest.NewRecorder()
	writeClientState(response, []database.Client{{
		ClientID:       "excluded-client",
		Enabled:        false,
		LastSeenAt:     &old,
		NetworkStatus:  "unknown",
		ADStatus:       "unknown",
		CameraStatus:   "unknown",
		KerberosStatus: "unknown",
	}}, now)
	body := response.Body.String()
	for _, expected := range []string{
		`sw_identity_clients{state="disabled"} 1`,
		`sw_identity_clients{state="stale"} 0`,
		`sw_identity_clients{state="never"} 0`,
		`sw_identity_clients{state="unhealthy"} 0`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q in metrics:\n%s", expected, body)
		}
	}
}

func TestUnmatchedPathsCannotIncreaseLabelCardinality(t *testing.T) {
	registry := New("test", "sqlite", nil)
	handler := registry.Middleware(http.NotFoundHandler())
	for index := 0; index < 500; index++ {
		path := "/private/" + strings.Repeat("x", index%80) + string(rune('a'+index%26))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.requests) != 1 {
		t.Fatalf("unmatched paths created %d label sets", len(registry.requests))
	}
	for key := range registry.requests {
		if key.component != "unmatched" || key.outcome != "invalid" {
			t.Fatalf("unexpected bounded labels: %+v", key)
		}
	}
}

func TestCombineFailsClosed(t *testing.T) {
	good := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("metric_one 1\n")) })
	bad := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private failure", http.StatusInternalServerError)
	})
	response := httptest.NewRecorder()
	Combine(good, bad).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private failure") {
		t.Fatal("combined metrics did not fail closed")
	}
}

func TestFailedMetricsAuthenticationIsRateLimited(t *testing.T) {
	protected := LimitAuthentication(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	for index := 0; index < 30; index++ {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		request.RemoteAddr = "192.0.2.10:1234"
		protected.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d", index, response.Code)
		}
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.RemoteAddr = "192.0.2.10:9999"
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "600" {
		t.Fatal("failed metrics authentication was not rate limited")
	}
}

func TestAuditFailureCounterHasNoDynamicLabels(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry := New("test", "sqlite", nil)
	registry.ObserveAuditFailure()
	registry.ObserveAuditFailure()
	response := httptest.NewRecorder()
	registry.Handler(store).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(response.Body.String(), "sw_identity_audit_write_failures_total 2") {
		t.Fatal("audit failures were not exposed as a bounded counter")
	}
}
