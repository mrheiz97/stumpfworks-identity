package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	frameworkpg "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresIdentityAdapter(t *testing.T) {
	dsn := os.Getenv("IDENTITY_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL test database not configured")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() != "55441" || parsed.Path != "/postgres" {
		t.Fatal("tests require the disposable loopback PostgreSQL cluster on port 55441")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("test PostgreSQL connection failed")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("identity_test_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Error("test schema cleanup failed")
		}
	}()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	pool, err := frameworkpg.Open(ctx, frameworkpg.Options{URL: u.String(), MaxConnections: 8, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 1 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal("test framework pool failed")
	}
	defer pool.Close()
	if _, err := pool.Native().Exec(ctx, "CREATE TABLE users(unverified_column text)"); err != nil {
		t.Fatal(err)
	}
	if err := MigratePostgres(ctx, pool); err == nil {
		t.Fatal("unverified existing table adopted by initial migration")
	}
	if _, err := pool.Native().Exec(ctx, "DROP TABLE users"); err != nil {
		t.Fatal(err)
	}
	if err := MigratePostgres(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := MigratePostgres(ctx, pool); err != nil {
		t.Fatal("repeat migration failed")
	}
	store, err := NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser(ctx, "fixture", "Synthetic User", "cn=fixture,dc=example,dc=test")
	if err != nil {
		t.Fatal(err)
	}
	if found, err := store.UserByUsername(ctx, "FIXTURE"); err != nil || found.ID != user.ID {
		t.Fatal("case-normalized lookup failed")
	}
	if _, err := store.GetUser(ctx, 999999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("missing-user error contract changed")
	}
	var wg sync.WaitGroup
	subjects := make(chan string, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subject, err := store.EnsureOIDCSubject(ctx, user.ID)
			if err != nil {
				failures <- err
			} else {
				subjects <- subject
			}
		}()
	}
	wg.Wait()
	close(subjects)
	close(failures)
	for range failures {
		t.Fatal("concurrent subject assignment failed")
	}
	var subject string
	for next := range subjects {
		if subject == "" {
			subject = next
		}
		if next != subject || next == "" {
			t.Fatal("subject identity diverged")
		}
	}
	if err := store.CreateOIDCClient(ctx, "fixture-app", "synthetic-hash", "https://example.test/callback", "openid"); err != nil {
		t.Fatal(err)
	}
	client, err := store.OIDCClientByID(ctx, "fixture-app")
	if err != nil || !client.Enabled || client.SecretHash != "synthetic-hash" {
		t.Fatal("client registration roundtrip failed")
	}
	code := OIDCCode{CodeHash: "synthetic-code", ClientID: "fixture-app", UserID: user.ID, RedirectURI: "https://example.test/callback", Scope: "openid", Nonce: "synthetic-nonce", CodeChallenge: "synthetic-challenge", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.CreateOIDCCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeOIDCCode(ctx, code.CodeHash, "wrong-app", code.RedirectURI, time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("wrong client accepted")
	}
	if _, err := store.ConsumeOIDCCode(ctx, code.CodeHash, code.ClientID, "https://wrong.test/callback", time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("wrong callback accepted")
	}
	var won atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := store.ConsumeOIDCCode(ctx, code.CodeHash, code.ClientID, code.RedirectURI, time.Now())
			if err == nil {
				won.Add(1)
				if result.UserID != user.ID {
					t.Error("code user changed")
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				t.Error("unexpected code-consumption error")
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("code winners=%d, want 1", won.Load())
	}
	code.CodeHash = "expired-code"
	code.ExpiresAt = time.Now().Add(-time.Minute)
	if err := store.CreateOIDCCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeOIDCCode(ctx, code.CodeHash, code.ClientID, code.RedirectURI, time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("expired code accepted")
	}
	t.Run("bounded atomic SQLite import", func(t *testing.T) {
		source, err := Open(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		user, err := source.CreateUser(ctx, "import-fixture", "Synthetic import user", "cn=fixture,dc=example,dc=test")
		if err != nil {
			t.Fatal(err)
		}
		if err := source.SetUserPIN(ctx, user.ID, "synthetic-pin-hash"); err != nil {
			t.Fatal(err)
		}
		subject, err := source.EnsureOIDCSubject(ctx, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		badge, err := source.CreateBadge(ctx, user.ID, "synthetic-badge-hash", "fixture")
		if err != nil {
			t.Fatal(err)
		}
		source.Audit(ctx, "fixture", "fixture", user.Username, "fixture-client", true, "", "synthetic audit")
		if _, err := source.CreateClient(ctx, "fixture-client", "synthetic-client-hash"); err != nil {
			t.Fatal(err)
		}
		if err := source.CreateSelfServiceSession(ctx, "synthetic-session", user.Username, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := source.CreateOIDCClient(ctx, "import-app", "synthetic-secret", "https://example.test/callback", "openid"); err != nil {
			t.Fatal(err)
		}
		code := OIDCCode{CodeHash: "import-code", ClientID: "import-app", UserID: user.ID, RedirectURI: "https://example.test/callback", Scope: "openid", Nonce: "synthetic-nonce", CodeChallenge: "synthetic-challenge", ExpiresAt: time.Now().Add(time.Minute)}
		if err := source.CreateOIDCCode(ctx, code); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 100); !errors.Is(err, ErrImportFailed) {
			t.Fatal("nonempty import target accepted")
		}
		if _, err := pool.Native().Exec(ctx, "TRUNCATE users,badges,audit_log,clients,self_service_sessions,oidc_clients,oidc_codes RESTART IDENTITY CASCADE"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 1); !errors.Is(err, ErrImportFailed) {
			t.Fatal("row budget not enforced")
		}
		var remaining int
		if err := pool.Native().QueryRow(ctx, "SELECT count(*) FROM users").Scan(&remaining); err != nil || remaining != 0 {
			t.Fatal("failed import left rows")
		}
		if _, err := source.DB.ExecContext(ctx, "UPDATE audit_log SET details=?", strings.Repeat("x", maximumImportRowBytes+1)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 100); !errors.Is(err, ErrImportFailed) {
			t.Fatal("oversized SQLite record accepted")
		}
		if err := pool.Native().QueryRow(ctx, "SELECT count(*) FROM users").Scan(&remaining); err != nil || remaining != 0 {
			t.Fatal("oversized record left partial import")
		}
		// The connection-local SQLite limit must be restored after the failure.
		if _, err := source.DB.ExecContext(ctx, "UPDATE audit_log SET details=?", strings.Repeat("y", maximumImportRowBytes+1)); err != nil {
			t.Fatal("import leaked its SQLite length limit into source pool")
		}
		if _, err := source.DB.ExecContext(ctx, "UPDATE audit_log SET details='synthetic audit'"); err != nil {
			t.Fatal(err)
		}
		if _, err := source.DB.ExecContext(ctx, "ALTER TABLE users ADD COLUMN future_field TEXT"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 100); !errors.Is(err, ErrImportFailed) {
			t.Fatal("unknown source field silently discarded")
		}
		if _, err := source.DB.ExecContext(ctx, "ALTER TABLE users DROP COLUMN future_field"); err != nil {
			t.Fatal(err)
		}
		if _, err := source.DB.ExecContext(ctx, "ALTER TABLE users ADD COLUMN future_derived TEXT GENERATED ALWAYS AS (username || '-derived') VIRTUAL"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 100); !errors.Is(err, ErrImportFailed) {
			t.Fatal("generated source field silently discarded")
		}
		if _, err := source.DB.ExecContext(ctx, "ALTER TABLE users DROP COLUMN future_derived; UPDATE sqlite_sequence SET seq=1000 WHERE name='users'"); err != nil {
			t.Fatal(err)
		}
		// A target trigger deliberately changes a copied field. Equal row counts
		// are insufficient: the full-field verifier must reject and roll back.
		if _, err := pool.Native().Exec(ctx, `CREATE FUNCTION corrupt_import_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.display_name := 'corrupted synthetic fixture'; RETURN NEW; END $$;
CREATE TRIGGER corrupt_import_fixture BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION corrupt_import_fixture()`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 100); !errors.Is(err, ErrImportFailed) {
			t.Fatal("field-changing target trigger escaped verification")
		}
		if err := pool.Native().QueryRow(ctx, "SELECT count(*) FROM users").Scan(&remaining); err != nil || remaining != 0 {
			t.Fatal("verification failure left imported rows")
		}
		if _, err := pool.Native().Exec(ctx, "DROP TRIGGER corrupt_import_fixture ON users; DROP FUNCTION corrupt_import_fixture()"); err != nil {
			t.Fatal(err)
		}
		counts, err := store.ImportSQLite(ctx, source.DB, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, table := range importTables {
			if counts[table] != 1 {
				t.Fatalf("unexpected count for %s", table)
			}
		}
		found, err := store.GetUser(ctx, user.ID)
		if err != nil || found.OIDCSubject != subject || found.PINHash != "synthetic-pin-hash" {
			t.Fatal("import changed user identity/hash")
		}
		var hash string
		if err := pool.Native().QueryRow(ctx, "SELECT token_hash FROM badges WHERE id=$1 AND user_id=$2", badge.ID, user.ID).Scan(&hash); err != nil || hash != "synthetic-badge-hash" {
			t.Fatal("import changed badge binding/hash")
		}
		t.Run("synthetic pg_dump restoration", func(t *testing.T) {
			testPostgresBackupRestore(t, ctx, dsn, schema, pool)
		})
		if _, err := store.ConsumeOIDCCode(ctx, code.CodeHash, code.ClientID, code.RedirectURI, time.Now()); err != nil {
			t.Fatal("imported code cannot be consumed")
		}
		newUser, err := store.CreateUser(ctx, "after-import", "Sequence fixture", "")
		if err != nil || newUser.ID <= 1000 {
			t.Fatal("import sequence not reset")
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 100); !errors.Is(err, ErrImportFailed) {
			t.Fatal("repeat import overwrote data")
		}
	})
	t.Run("session and OIDC contract", func(t *testing.T) {
		testSessionOIDCContract(t, store)
	})
	t.Run("badge contract", func(t *testing.T) {
		testBadgeContract(t, store)
	})
	t.Run("client contract", func(t *testing.T) {
		testClientContract(t, store)
	})
	t.Run("audit read contract and visible failure", func(t *testing.T) {
		testAuditReadContract(t, store, func(event Audit) error { return store.WriteAudit(ctx, event) })
		if counts, err := store.Counts(ctx); err != nil || counts["today"] != 25 || counts["failed"] != 1 {
			t.Fatal("UTC audit counters failed")
		}
		if _, err := pool.Native().Exec(ctx, `CREATE FUNCTION fail_audit_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit rejection'; END $$;
CREATE TRIGGER fail_audit_fixture BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_audit_fixture()`); err != nil {
			t.Fatal(err)
		}
		if err := store.WriteAudit(ctx, Audit{EventType: "synthetic_rejected"}); err == nil {
			t.Fatal("audit write failure was swallowed")
		}
		if _, err := pool.Native().Exec(ctx, "DROP TRIGGER fail_audit_fixture ON audit_log; DROP FUNCTION fail_audit_fixture()"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("concurrent badge mutation", func(t *testing.T) {
		created := make(chan Badge, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				badge, err := store.CreateBadge(ctx, user.ID, "synthetic-concurrent-hash", "concurrent fixture")
				if err != nil {
					t.Error("concurrent badge creation failed")
					return
				}
				created <- badge
			}()
		}
		wg.Wait()
		close(created)
		seen := make(map[string]bool)
		var original Badge
		for badge := range created {
			if seen[badge.BadgeCode] {
				t.Fatal("concurrent badge code reused")
			}
			seen[badge.BadgeCode] = true
			original = badge
		}
		if len(seen) != 8 {
			t.Fatal("badge creation lost a request")
		}
		won.Store(0)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := store.ReplaceBadgePending(ctx, original.ID, "synthetic-pending-hash", "concurrent replacement")
				if err == nil {
					won.Add(1)
				} else if !errors.Is(err, sql.ErrNoRows) {
					t.Error("unexpected concurrent replacement error")
				}
			}()
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatal("original badge replaced more than once")
		}
	})
	t.Run("atomic mutation plus audit", func(t *testing.T) {
		testAtomicLostBadge(t, store, func(reject bool) {
			query := "DROP TRIGGER IF EXISTS fail_atomic_audit ON audit_log; DROP FUNCTION IF EXISTS fail_atomic_audit()"
			if reject {
				query = `CREATE FUNCTION fail_atomic_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit rejection'; END $$;
CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_atomic_audit()`
			}
			if _, err := pool.Native().Exec(ctx, query); err != nil {
				t.Fatal("PostgreSQL atomic audit fixture setup failed")
			}
		})
	})
	t.Run("runtime role cannot migrate", func(t *testing.T) {
		role := fmt.Sprintf("identity_runtime_%d", time.Now().UnixNano())
		quotedRole := pgx.Identifier{role}.Sanitize()
		passwordBytes := make([]byte, 24)
		if _, err := rand.Read(passwordBytes); err != nil {
			t.Fatal(err)
		}
		password := hex.EncodeToString(passwordBytes)
		// password contains only lowercase hexadecimal generated for this
		// disposable role, so quoting cannot change SQL structure.
		if _, err := admin.Exec(ctx, "CREATE ROLE "+quotedRole+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '"+password+"'"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := admin.Exec(cleanup, "DROP OWNED BY "+quotedRole+"; DROP ROLE "+quotedRole); err != nil {
				t.Error("test role cleanup failed")
			}
		}()
		if _, err := admin.Exec(ctx, "GRANT USAGE ON SCHEMA "+identifier+" TO "+quotedRole); err != nil {
			t.Fatal(err)
		}
		for _, table := range importTables {
			if _, err := admin.Exec(ctx, "GRANT SELECT,INSERT,UPDATE,DELETE ON "+pgx.Identifier{schema, table}.Sanitize()+" TO "+quotedRole); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := admin.Exec(ctx, "GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA "+identifier+" TO "+quotedRole); err != nil {
			t.Fatal(err)
		}
		runtimeURL := *u
		// Connect as the restricted role itself, never as an administrator with
		// SET ROLE. A temporary random password supports both trust and SCRAM CI.
		runtimeURL.User = url.UserPassword(role, password)
		runtimePool, err := frameworkpg.Open(ctx, frameworkpg.Options{URL: runtimeURL.String(), MaxConnections: 2, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 1 << 20, AllowInsecure: true})
		if err != nil {
			var failure *pgconn.PgError
			if errors.As(err, &failure) {
				t.Fatalf("restricted runtime pool failed: SQLSTATE %s", failure.Code)
			}
			t.Fatalf("restricted runtime pool failed: %T", err)
		}
		defer runtimePool.Close()
		var effectiveRole string
		if err := runtimePool.Native().QueryRow(ctx, "SELECT current_user").Scan(&effectiveRole); err != nil || effectiveRole != role {
			t.Fatal("runtime role not applied")
		}
		runtimeStore, err := NewPostgresStore(runtimePool)
		if err != nil {
			t.Fatal(err)
		}
		runtimeUser, err := runtimeStore.CreateUser(ctx, "restricted-runtime-user", "Synthetic runtime", "")
		if err != nil {
			t.Fatal("runtime user insert denied")
		}
		if err := runtimeStore.SetUserPIN(ctx, runtimeUser.ID, "synthetic-runtime-pin"); err != nil {
			t.Fatal("runtime PIN update denied")
		}
		if _, err := runtimeStore.EnsureOIDCSubject(ctx, runtimeUser.ID); err != nil {
			t.Fatal("runtime subject assignment denied")
		}
		if _, err := runtimeStore.CreateBadge(ctx, runtimeUser.ID, "synthetic-runtime-badge", "runtime"); err != nil {
			t.Fatal("runtime badge sequence denied")
		}
		if _, err := runtimeStore.CreateClient(ctx, "restricted-runtime-client", "synthetic-runtime-client-hash"); err != nil {
			t.Fatal("runtime client creation denied")
		}
		if err := runtimeStore.CreateSelfServiceSession(ctx, "restricted-runtime-session", runtimeUser.Username, time.Now().Add(time.Hour)); err != nil {
			t.Fatal("runtime session creation denied")
		}
		if err := runtimeStore.CreateOIDCClient(ctx, "restricted-runtime-app", "synthetic-runtime-secret", "https://example.test/callback", "openid"); err != nil {
			t.Fatal("runtime OIDC client creation denied")
		}
		runtimeCode := OIDCCode{CodeHash: "restricted-runtime-code", ClientID: "restricted-runtime-app", UserID: runtimeUser.ID, RedirectURI: "https://example.test/callback", Scope: "openid", ExpiresAt: time.Now().Add(time.Minute)}
		if err := runtimeStore.CreateOIDCCode(ctx, runtimeCode); err != nil {
			t.Fatal("runtime code creation denied")
		}
		if _, err := runtimeStore.ConsumeOIDCCode(ctx, runtimeCode.CodeHash, runtimeCode.ClientID, runtimeCode.RedirectURI, time.Now()); err != nil {
			t.Fatal("runtime code consumption denied")
		}
		if err := runtimeStore.WriteAudit(ctx, Audit{EventType: "runtime_fixture", Username: runtimeUser.Username}); err != nil {
			t.Fatal("runtime audit insert denied")
		}
		if _, err := runtimeStore.Counts(ctx); err != nil {
			t.Fatal("runtime read denied")
		}
		_, err = runtimePool.Native().Exec(ctx, "CREATE TABLE runtime_forbidden(id bigint)")
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("runtime schema creation was not permission-denied")
		}
		if err := MigratePostgres(ctx, runtimePool); err == nil {
			t.Fatal("runtime role could run migrations")
		}
	})
	t.Run("legacy client import and fail-closed source shape", func(t *testing.T) {
		if _, err := pool.Native().Exec(ctx, "TRUNCATE users,badges,audit_log,clients,self_service_sessions,oidc_clients,oidc_codes RESTART IDENTITY CASCADE"); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "synthetic-legacy.db")
		legacy, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = legacy.ExecContext(ctx, `CREATE TABLE clients(id INTEGER PRIMARY KEY AUTOINCREMENT,client_id TEXT NOT NULL UNIQUE,token_hash TEXT NOT NULL,version TEXT NOT NULL DEFAULT '',network_status TEXT NOT NULL DEFAULT 'unknown',ad_status TEXT NOT NULL DEFAULT 'unknown',camera_status TEXT NOT NULL DEFAULT 'unknown',kerberos_status TEXT NOT NULL DEFAULT 'unknown',created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,last_seen_at DATETIME); INSERT INTO clients(id,client_id,token_hash) VALUES(42,'legacy-import-client','synthetic-legacy-hash')`)
		legacy.Close()
		if err != nil {
			t.Fatal(err)
		}
		source, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if _, err := source.DB.ExecContext(ctx, "CREATE TABLE future_app_records(id INTEGER)"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 100); !errors.Is(err, ErrImportFailed) {
			t.Fatal("unknown source table silently ignored")
		}
		if _, err := source.DB.ExecContext(ctx, "DROP TABLE future_app_records"); err != nil {
			t.Fatal(err)
		}
		first, err := source.CreateUser(ctx, "ambiguous-fixture", "Synthetic case fixture", "")
		if err != nil {
			t.Fatal(err)
		}
		second, err := source.CreateUser(ctx, "AMBIGUOUS-FIXTURE", "Synthetic case fixture", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.ImportSQLite(ctx, source.DB, 100); !errors.Is(err, ErrImportFailed) {
			t.Fatal("ambiguous account import accepted")
		}
		for _, table := range importTables {
			var count int
			if err := pool.Native().QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed source validation left target rows")
			}
		}
		if _, err := source.DB.ExecContext(ctx, "DELETE FROM users WHERE id IN (?,?)", first.ID, second.ID); err != nil {
			t.Fatal(err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := store.ImportSQLite(cancelled, source.DB, 1); !errors.Is(err, context.Canceled) {
			t.Fatal("import cancellation contract changed")
		}
		counts, err := store.ImportSQLite(ctx, source.DB, 1)
		if err != nil || counts["clients"] != 1 || counts["users"] != 0 {
			t.Fatal("legacy client import failed")
		}
		var updated *time.Time
		if err := pool.Native().QueryRow(ctx, "SELECT updated_at FROM clients WHERE id=42").Scan(&updated); err != nil || updated != nil {
			t.Fatal("legacy null timestamp replaced")
		}
		client, err := store.ClientByID(ctx, "legacy-import-client")
		if err != nil || client.ID != 42 || client.TokenHash != "synthetic-legacy-hash" || !client.Enabled {
			t.Fatal("legacy client data changed")
		}
		next, err := store.CreateClient(ctx, "after-legacy-import", "synthetic-next-hash")
		if err != nil || next.ID <= 42 {
			t.Fatal("legacy client sequence lost original IDs")
		}
	})
}
