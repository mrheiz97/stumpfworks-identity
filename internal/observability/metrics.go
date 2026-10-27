package observability

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

var durationBuckets = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type operationKey struct{ component, outcome string }
type observation struct {
	count   uint64
	sum     float64
	buckets [len(durationBuckets)]uint64
}

// Registry contains only bounded, non-identifying Identity metrics. Generic
// HTTP, LDAP and PostgreSQL pool metrics remain owned by the Framework.
type Registry struct {
	mu                                           sync.Mutex
	started                                      time.Time
	version                                      string
	backend                                      string
	modules                                      map[string]bool
	requests                                     map[operationKey]observation
	errors                                       map[string]uint64
	auditFailures                                uint64
	now                                          func() time.Time
	certificateFile, backupPath, maintenanceFile string
}

func (r *Registry) ObserveAuditFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auditFailures++
}

type authLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	now      func() time.Time
}

// LimitAuthentication bounds repeated failed bearer attempts per source while
// leaving successful Prometheus scrapes unaffected.
func LimitAuthentication(next http.Handler) http.Handler {
	limiter := &authLimiter{attempts: map[string][]time.Time{}, now: time.Now}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := sourceKey(r.RemoteAddr)
		if limiter.blocked(key) {
			w.Header().Set("Retry-After", "600")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		writer := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(writer, r)
		if writer.status == http.StatusUnauthorized {
			limiter.failed(key)
		}
	})
}

func (l *authLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key)
	return len(l.attempts[key]) >= 30
}

func (l *authLimiter) failed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key)
	l.attempts[key] = append(l.attempts[key], l.now())
}

func (l *authLimiter) prune(key string) {
	cut := l.now().Add(-10 * time.Minute)
	kept := l.attempts[key][:0]
	for _, attempt := range l.attempts[key] {
		if attempt.After(cut) {
			kept = append(kept, attempt)
		}
	}
	if len(kept) == 0 {
		delete(l.attempts, key)
	} else {
		l.attempts[key] = kept
	}
}

func sourceKey(address string) string {
	if index := strings.LastIndex(address, ":"); index > 0 {
		return address[:index]
	}
	return address
}

// ConfigureOperationalFiles enables fixed-label certificate, backup and
// maintenance gauges. Paths and filesystem errors are never exposed.
func (r *Registry) ConfigureOperationalFiles(certificateFile, backupPath, maintenanceFile string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.certificateFile, r.backupPath, r.maintenanceFile = certificateFile, backupPath, maintenanceFile
}

func New(version, backend string, modules map[string]bool) *Registry {
	boundedModules := map[string]bool{}
	for _, name := range []string{"directory", "emergency_admin", "metrics", "oidc", "passkeys", "pkinit"} {
		boundedModules[name] = modules[name]
	}
	if backend != "postgres" {
		backend = "sqlite"
	}
	return &Registry{started: time.Now().UTC(), version: version, backend: backend, modules: boundedModules, requests: map[operationKey]observation{}, errors: map[string]uint64{}, now: time.Now}
}

func (r *Registry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		writer := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(writer, request)
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		r.observe(componentFor(request.Pattern), outcomeFor(status), time.Since(started))
	})
}

func (r *Registry) observe(component, outcome string, duration time.Duration) {
	seconds := duration.Seconds()
	if seconds < 0 {
		seconds = 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := operationKey{component: component, outcome: outcome}
	item := r.requests[key]
	item.count++
	item.sum += seconds
	for index, upper := range durationBuckets {
		if seconds <= upper {
			item.buckets[index]++
		}
	}
	r.requests[key] = item
}

func componentFor(pattern string) string {
	switch {
	case strings.Contains(pattern, "/passkeys/"):
		return "passkey"
	case strings.HasPrefix(pattern, "POST /api/v1/auth/pkinit"):
		return "pkinit"
	case strings.HasPrefix(pattern, "POST /api/v1/auth/badge"):
		return "badge"
	case strings.Contains(pattern, "/oauth2/") || strings.Contains(pattern, "/oidc-") || strings.Contains(pattern, "/.well-known/"):
		return "oidc"
	case strings.Contains(pattern, "/api/v1/client/status"):
		return "client"
	case strings.Contains(pattern, "/self-service"):
		return "self_service"
	case strings.Contains(pattern, "/emergency-login"):
		return "emergency_admin"
	case strings.Contains(pattern, "/login") || strings.Contains(pattern, "/logout"):
		return "admin"
	case strings.Contains(pattern, "/health"):
		return "health"
	case pattern == "":
		return "unmatched"
	default:
		return "administration"
	}
}

func outcomeFor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "success"
	case status >= 300 && status < 400:
		return "redirect"
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "denied"
	case status == http.StatusTooManyRequests:
		return "rate_limited"
	case status >= 400 && status < 500:
		return "invalid"
	default:
		return "failure"
	}
}

// Handler exposes Identity-specific metrics and bounded aggregate store state.
func (r *Registry) Handler(store database.ApplicationStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		r.mu.Lock()
		requests := make(map[operationKey]observation, len(r.requests))
		for key, item := range r.requests {
			requests[key] = item
		}
		errorsSnapshot := make(map[string]uint64, len(r.errors))
		for key, value := range r.errors {
			errorsSnapshot[key] = value
		}
		started, version, backend, auditFailures := r.started, r.version, r.backend, r.auditFailures
		certificateFile, backupPath, maintenanceFile := r.certificateFile, r.backupPath, r.maintenanceFile
		modules := make(map[string]bool, len(r.modules))
		for key, value := range r.modules {
			modules[key] = value
		}
		r.mu.Unlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintln(w, "# HELP sw_identity_info Static Identity build and database information.")
		fmt.Fprintln(w, "# TYPE sw_identity_info gauge")
		fmt.Fprintf(w, "sw_identity_info{version=%s,backend=%s} 1\n", quote(version), quote(backend))
		fmt.Fprintln(w, "# HELP sw_identity_start_time_seconds Identity process start time as Unix seconds.")
		fmt.Fprintln(w, "# TYPE sw_identity_start_time_seconds gauge")
		fmt.Fprintf(w, "sw_identity_start_time_seconds %d\n", started.Unix())
		fmt.Fprintln(w, "# HELP sw_identity_audit_write_failures_total Failed explicit security audit writes.")
		fmt.Fprintln(w, "# TYPE sw_identity_audit_write_failures_total counter")
		fmt.Fprintf(w, "sw_identity_audit_write_failures_total %d\n", auditFailures)

		moduleNames := sortedBoolKeys(modules)
		fmt.Fprintln(w, "# HELP sw_identity_module_enabled Whether an optional Identity module is enabled.")
		fmt.Fprintln(w, "# TYPE sw_identity_module_enabled gauge")
		for _, name := range moduleNames {
			fmt.Fprintf(w, "sw_identity_module_enabled{module=%s} %d\n", quote(name), boolNumber(modules[name]))
		}
		writeOperations(w, requests)

		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()
		counts, countErr := store.Counts(ctx)
		clients, clientErr := store.Clients(ctx)
		if countErr != nil {
			r.incrementError("database_counts")
			errorsSnapshot["database_counts"]++
		} else {
			writeCounts(w, counts)
		}
		if clientErr != nil {
			r.incrementError("client_state")
			errorsSnapshot["client_state"]++
		} else {
			writeClientState(w, clients, r.now().UTC())
		}
		for collector, err := range writeOperationalFiles(w, certificateFile, backupPath, maintenanceFile) {
			if err != nil {
				r.incrementError(collector)
				errorsSnapshot[collector]++
			}
		}
		fmt.Fprintln(w, "# HELP sw_identity_collection_errors_total Failed scrape-time aggregate collections.")
		fmt.Fprintln(w, "# TYPE sw_identity_collection_errors_total counter")
		for _, collector := range []string{"backup", "certificate", "client_state", "database_counts", "maintenance"} {
			fmt.Fprintf(w, "sw_identity_collection_errors_total{collector=%s} %d\n", quote(collector), errorsSnapshot[collector])
		}
	})
}

func writeOperationalFiles(w http.ResponseWriter, certificateFile, backupPath, maintenanceFile string) map[string]error {
	errorsByCollector := map[string]error{}
	if certificateFile != "" {
		file, err := os.Open(certificateFile)
		if err == nil {
			defer file.Close()
			var contents []byte
			contents, err = io.ReadAll(io.LimitReader(file, (1<<20)+1))
			if err == nil && len(contents) <= 1<<20 {
				block, _ := pem.Decode(contents)
				if block == nil {
					err = fmt.Errorf("certificate PEM unavailable")
				} else if certificate, parseErr := x509.ParseCertificate(block.Bytes); parseErr != nil {
					err = parseErr
				} else {
					fmt.Fprintln(w, "# HELP sw_identity_certificate_not_after_seconds Server certificate expiry as Unix seconds.")
					fmt.Fprintln(w, "# TYPE sw_identity_certificate_not_after_seconds gauge")
					fmt.Fprintf(w, "sw_identity_certificate_not_after_seconds{certificate=\"server\"} %d\n", certificate.NotAfter.Unix())
				}
			} else if err == nil {
				err = fmt.Errorf("certificate exceeds limit")
			}
		}
		errorsByCollector["certificate"] = err
	}
	if backupPath != "" {
		info, err := os.Stat(backupPath)
		if err == nil {
			fmt.Fprintln(w, "# HELP sw_identity_backup_timestamp_seconds Last successful database backup timestamp as Unix seconds.")
			fmt.Fprintln(w, "# TYPE sw_identity_backup_timestamp_seconds gauge")
			fmt.Fprintf(w, "sw_identity_backup_timestamp_seconds{backup=\"database\"} %d\n", info.ModTime().Unix())
		}
		errorsByCollector["backup"] = err
	}
	if maintenanceFile != "" {
		_, err := os.Stat(maintenanceFile)
		maintenance := 0
		if err == nil {
			maintenance = 1
		} else if os.IsNotExist(err) {
			err = nil
		}
		fmt.Fprintln(w, "# HELP sw_identity_maintenance_mode Whether Identity is intentionally in maintenance mode.")
		fmt.Fprintln(w, "# TYPE sw_identity_maintenance_mode gauge")
		fmt.Fprintf(w, "sw_identity_maintenance_mode %d\n", maintenance)
		errorsByCollector["maintenance"] = err
	}
	return errorsByCollector
}

func (r *Registry) incrementError(collector string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors[collector]++
}

func writeCounts(w http.ResponseWriter, counts map[string]int64) {
	fmt.Fprintln(w, "# HELP sw_identity_objects Current aggregate Identity objects by bounded kind.")
	fmt.Fprintln(w, "# TYPE sw_identity_objects gauge")
	for _, item := range []struct{ label, key string }{{"active_badges", "active"}, {"badges", "badges"}, {"revoked_badges", "revoked"}, {"users", "users"}} {
		fmt.Fprintf(w, "sw_identity_objects{kind=%s} %d\n", quote(item.label), nonNegative(counts[item.key]))
	}
	fmt.Fprintln(w, "# HELP sw_identity_auth_events_today Badge authentication events since UTC day start.")
	fmt.Fprintln(w, "# TYPE sw_identity_auth_events_today gauge")
	fmt.Fprintf(w, "sw_identity_auth_events_today{outcome=\"success\"} %d\n", nonNegative(counts["today"]))
	fmt.Fprintf(w, "sw_identity_auth_events_today{outcome=\"failed\"} %d\n", nonNegative(counts["failed"]))
}

func writeClientState(w http.ResponseWriter, clients []database.Client, now time.Time) {
	states := map[string]int64{"disabled": 0, "fresh": 0, "never": 0, "stale": 0, "unhealthy": 0}
	for _, client := range clients {
		if !client.Enabled {
			states["disabled"]++
			continue
		}
		if client.LastSeenAt == nil {
			states["never"]++
		} else if now.Sub(client.LastSeenAt.UTC()) > 3*time.Minute {
			states["stale"]++
		} else {
			states["fresh"]++
		}
		if client.NetworkStatus != "ok" || client.ADStatus != "ok" || client.CameraStatus != "ok" || client.KerberosStatus != "ok" {
			states["unhealthy"]++
		}
	}
	fmt.Fprintln(w, "# HELP sw_identity_clients Current managed clients by bounded operational state.")
	fmt.Fprintln(w, "# TYPE sw_identity_clients gauge")
	for _, state := range []string{"fresh", "stale", "never", "unhealthy", "disabled"} {
		fmt.Fprintf(w, "sw_identity_clients{state=%s} %d\n", quote(state), states[state])
	}
}

func writeOperations(w http.ResponseWriter, values map[operationKey]observation) {
	keys := make([]operationKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].component != keys[j].component {
			return keys[i].component < keys[j].component
		}
		return keys[i].outcome < keys[j].outcome
	})
	fmt.Fprintln(w, "# HELP sw_identity_operations_total Completed Identity operations by bounded component and outcome.")
	fmt.Fprintln(w, "# TYPE sw_identity_operations_total counter")
	fmt.Fprintln(w, "# HELP sw_identity_operation_duration_seconds Identity operation duration in seconds.")
	fmt.Fprintln(w, "# TYPE sw_identity_operation_duration_seconds histogram")
	for _, key := range keys {
		item := values[key]
		labels := "component=" + quote(key.component) + ",outcome=" + quote(key.outcome)
		fmt.Fprintf(w, "sw_identity_operations_total{%s} %d\n", labels, item.count)
		for index, upper := range durationBuckets {
			fmt.Fprintf(w, "sw_identity_operation_duration_seconds_bucket{%s,le=%s} %d\n", labels, quote(strconv.FormatFloat(upper, 'f', -1, 64)), item.buckets[index])
		}
		fmt.Fprintf(w, "sw_identity_operation_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, item.count)
		fmt.Fprintf(w, "sw_identity_operation_duration_seconds_sum{%s} %s\n", labels, strconv.FormatFloat(item.sum, 'f', -1, 64))
		fmt.Fprintf(w, "sw_identity_operation_duration_seconds_count{%s} %d\n", labels, item.count)
	}
}

// Combine concatenates independently valid Prometheus text handlers without
// allowing either registry to control the other's headers or status.
func Combine(handlers ...http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var combined bytes.Buffer
		for _, handler := range handlers {
			if handler == nil {
				continue
			}
			capture := &bufferWriter{header: make(http.Header), status: http.StatusOK}
			handler.ServeHTTP(capture, r)
			if capture.status >= 400 {
				http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = combined.Write(capture.body.Bytes())
			if capture.body.Len() > 0 && !bytes.HasSuffix(capture.body.Bytes(), []byte("\n")) {
				_ = combined.WriteByte('\n')
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(combined.Bytes())
	})
}

type bufferWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *bufferWriter) Header() http.Header            { return w.header }
func (w *bufferWriter) WriteHeader(status int)         { w.status = status }
func (w *bufferWriter) Write(body []byte) (int, error) { return w.body.Write(body) }

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func sortedBoolKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func boolNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}
func nonNegative(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}
func quote(value string) string {
	value = strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(value)
	return "\"" + value + "\""
}
