package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	frameworkpg "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
)

// Test-only compatibility boundary. Do not expose a production adapter that
// silently discards audit errors; runtime policy remains an explicit next step.
type postgresProviderFixture struct {
	*database.PostgresStore
	t *testing.T
}

func (s postgresProviderFixture) Audit(ctx context.Context, event, badge, user, client string, success bool, ip, details string) {
	if err := s.WriteAudit(ctx, database.Audit{EventType: event, BadgeID: badge, Username: user, ClientID: client, Success: success, IPAddress: ip, Details: details}); err != nil {
		s.t.Error("synthetic provider audit write failed")
	}
}

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
	p.store = postgresProviderFixture{PostgresStore: st, t: t}
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
