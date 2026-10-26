package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/jackc/pgx/v5"
	frameworkpg "github.com/mrheiz97/stumpfworks-framework/data/postgres"
)

func TestPostgresAdministrativeAuthorizationContract(t *testing.T) {
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
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("identity_rbac_test_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, cleanupErr := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); cleanupErr != nil {
			t.Error(cleanupErr)
		}
	}()
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := frameworkpg.Open(ctx, frameworkpg.Options{URL: parsed.String(), MaxConnections: 4, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 1 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = database.MigratePostgres(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store, err := database.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	sessions, _ := adminauth.NewSessions("01234567890123456789012345678901", time.Hour)

	auditor := NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), roleDirectory{roles: []adminauth.Role{adminauth.RoleAuditor}}, sessions)
	auditorToken := sessions.Issue("auditor", time.Now())
	denied := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader("username=forbidden&display_name=Forbidden"))
	denied.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	denied.Header.Set("X-CSRF-Token", sessions.CSRF(auditorToken))
	denied.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: auditorToken})
	deniedResponse := httptest.NewRecorder()
	auditor.Handler().ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusForbidden {
		t.Fatalf("PostgreSQL auditor write returned %d", deniedResponse.Code)
	}
	if users, queryErr := store.Users(ctx); queryErr != nil || len(users) != 0 {
		t.Fatalf("denied PostgreSQL write changed users: %+v %v", users, queryErr)
	}

	operator := NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), roleDirectory{roles: []adminauth.Role{adminauth.RoleOperator}}, sessions)
	operatorToken := sessions.Issue("operator", time.Now())
	allowed := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader("username=created&display_name=Created+User"))
	allowed.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	allowed.Header.Set("X-CSRF-Token", sessions.CSRF(operatorToken))
	allowed.AddCookie(&http.Cookie{Name: "swbadge_admin", Value: operatorToken})
	allowedResponse := httptest.NewRecorder()
	operator.Handler().ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusSeeOther {
		t.Fatalf("PostgreSQL operator write returned %d: %s", allowedResponse.Code, allowedResponse.Body.String())
	}
	users, err := store.Users(ctx)
	if err != nil || len(users) != 1 || users[0].Username != "created" {
		t.Fatalf("PostgreSQL operator write missing: %+v %v", users, err)
	}
	audits, err := store.Audits(ctx)
	if err != nil || len(audits) != 1 || audits[0].EventType != "user_created" || !audits[0].Success {
		t.Fatalf("PostgreSQL operator audit missing or duplicated: %+v %v", audits, err)
	}
}
