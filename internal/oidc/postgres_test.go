package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	frameworkpg "github.com/mrheiz97/stumpfworks-framework/data/postgres"
)

func TestPostgresProviderProtocol(t *testing.T) {
	dsn := os.Getenv("IDENTITY_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL cluster not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Port() != "55441" || u.Path != "/postgres" {
		t.Fatal("provider tests require disposable loopback cluster on port 55441")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("test PostgreSQL unavailable")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("identity_protocol_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Error("protocol fixture cleanup failed")
		}
	}()
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	pool, err := frameworkpg.Open(ctx, frameworkpg.Options{URL: u.String(), MaxConnections: 8, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 1 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal("protocol fixture pool unavailable")
	}
	defer pool.Close()
	if err := database.MigratePostgres(ctx, pool); err != nil {
		t.Fatal(err)
	}
	st, err := database.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	p, sqlite, key, dir := testProvider(t)
	client, err := sqlite.OIDCClientByID(ctx, "stumpfworks-access")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateOIDCClient(ctx, client.ClientID, client.SecretHash, client.RedirectURIs, client.Scopes); err != nil {
		t.Fatal(err)
	}
	p.store = st
	setAuditRejection := func(reject bool) {
		t.Helper()
		query := "DROP TRIGGER IF EXISTS fail_oidc_audit_fixture ON audit_log; DROP FUNCTION IF EXISTS fail_oidc_audit_fixture()"
		if reject {
			query = `CREATE FUNCTION fail_oidc_audit_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit rejection'; END $$;
CREATE TRIGGER fail_oidc_audit_fixture BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_oidc_audit_fixture()`
		}
		if _, err := pool.Native().Exec(ctx, query); err != nil {
			t.Fatal("PostgreSQL OIDC audit fixture setup failed")
		}
	}
	t.Run("first login fails closed on audit rejection", func(t *testing.T) {
		setAuditRejection(true)
		values := authValues(strings.Repeat("f", 43))
		values.Set("username", "alice")
		values.Set("password", "correct")
		request := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := serve(p, request)
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" {
			t.Fatal("user-provision audit failure exposed authorization success")
		}
		if _, err := st.UserByUsername(ctx, "alice"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("user-provision audit failure left a partial user")
		}

		setAuditRejection(false)
		user, err := st.CreateUser(ctx, "alice", "Alice Example", "CN=Alice")
		if err != nil {
			t.Fatal(err)
		}
		setAuditRejection(true)
		response = serve(p, request)
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" {
			t.Fatal("subject audit failure exposed authorization success")
		}
		user, err = st.GetUser(ctx, user.ID)
		if err != nil || user.OIDCSubject != "" {
			t.Fatal("subject audit failure left a partial subject")
		}
		var codes int
		if err := pool.Native().QueryRow(ctx, "SELECT count(*) FROM oidc_codes").Scan(&codes); err != nil || codes != 0 {
			t.Fatal("first-login audit failure left a redeemable code")
		}
		setAuditRejection(false)
	})
	t.Run("client secret rotation", func(t *testing.T) {
		testOIDCClientSecretRotation(t, p, st)
	})
	verifier := strings.Repeat("v", 43)
	code := issueCode(t, p, verifier)
	if denied := exchangeSecret(p, code, verifier, "wrong"); denied.Code != 401 {
		t.Fatal("wrong secret accepted")
	}
	response := exchange(p, code, verifier)
	if response.Code != 200 {
		t.Fatal("PostgreSQL protocol exchange failed")
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	raw, ok := body["id_token"].(string)
	if !ok {
		t.Fatal("ID token missing")
	}
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal("signed token parse failed")
	}
	var claims map[string]any
	if err := token.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatal("signature verification failed")
	}
	accessToken, ok := body["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("PostgreSQL opaque access token missing")
	}
	if active := clientTokenRequest(p, "/oauth2/introspect", accessToken, "client-secret"); active.Code != http.StatusOK || !strings.Contains(active.Body.String(), `"active":true`) {
		t.Fatal("PostgreSQL introspection rejected active token")
	}
	if revoked := clientTokenRequest(p, "/oauth2/revoke", accessToken, "client-secret"); revoked.Code != http.StatusOK {
		t.Fatal("PostgreSQL token revocation failed")
	}
	if inactive := clientTokenRequest(p, "/oauth2/introspect", accessToken, "client-secret"); inactive.Code != http.StatusOK || !strings.Contains(inactive.Body.String(), `"active":false`) {
		t.Fatal("PostgreSQL revoked token remained active")
	}
	user, err := st.UserByUsername(ctx, "alice")
	if err != nil || claims["sub"] != user.OIDCSubject || claims["nonce"] != "nonce-1" || claims["iss"] != "https://identity.example.test" {
		t.Fatal("persistent identity claims changed")
	}
	if replay := exchange(p, code, verifier); replay.Code != 400 {
		t.Fatal("protocol code replay accepted")
	}
	code = issueCode(t, p, verifier)
	if bad := exchange(p, code, strings.Repeat("x", 43)); bad.Code != 400 {
		t.Fatal("wrong PKCE accepted")
	}
	if retry := exchange(p, code, verifier); retry.Code != 400 {
		t.Fatal("PKCE-rejected code reused")
	}
	code = issueCode(t, p, verifier)
	dir.disabled = true
	if inactive := exchange(p, code, verifier); inactive.Code != 400 {
		t.Fatal("inactive directory user accepted")
	}
	dir.disabled = false
	code = issueCode(t, p, verifier)
	var tokenAuditsBefore int
	if err := pool.Native().QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE event_type='oidc_token_issued' AND client_id='stumpfworks-access'").Scan(&tokenAuditsBefore); err != nil {
		t.Fatal("token audit baseline failed")
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		remoteAddress := fmt.Sprintf("192.0.2.%d:1234", i+10)
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Fresh TEST-NET client IPs isolate code concurrency from the
			// independently tested per-IP rate limiter. No policy is disabled.
			result := exchangeFrom(p, code, verifier, "client-secret", remoteAddress)
			if result.Code == 200 {
				winners.Add(1)
			} else if result.Code != 400 {
				t.Error("unexpected competing token response")
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("competing protocol exchanges did not have one winner")
	}
	var tokenAuditsAfter int
	if err := pool.Native().QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE event_type='oidc_token_issued' AND client_id='stumpfworks-access'").Scan(&tokenAuditsAfter); err != nil || tokenAuditsAfter != tokenAuditsBefore+1 {
		t.Fatal("competing protocol exchanges did not produce exactly one success audit")
	}
	clock := time.Now().UTC()
	p.now = func() time.Time { return clock }
	code = issueCode(t, p, verifier)
	clock = clock.Add(91 * time.Second)
	if expired := exchangeFrom(p, code, verifier, "client-secret", "192.0.2.98:1234"); expired.Code != 400 {
		t.Fatal("expired protocol code accepted")
	}
	testTokenRateLimit(t, p)
	t.Run("framework client over verified local TLS", func(t *testing.T) {
		testFrameworkClientContract(t, p, st)
	})
}
