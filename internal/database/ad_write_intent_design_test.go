package database

// Test-only protocol prototype. These tables are deliberately absent from runtime migrations.
import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestADWriteIntentDesignSQLite(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "design.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	testADWriteIntentDesign(t, db)
}

func TestPostgresADWriteIntentDesign(t *testing.T) {
	dsn := os.Getenv("IDENTITY_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Port() != "55441" || u.Path != "/postgres" {
		t.Fatal("disposable loopback PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("test connection failed")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("adwrite_design_%d", time.Now().UnixNano())
	id := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+id); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+id+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(8)
	testADWriteIntentDesign(t, db)
}

func testADWriteIntentDesign(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		`CREATE TABLE design_intent (id TEXT PRIMARY KEY, state TEXT NOT NULL)`,
		`CREATE TABLE design_audit (operation_id TEXT NOT NULL, event TEXT NOT NULL CHECK(event <> 'reject'))`,
		`INSERT INTO design_intent VALUES ('one','prepared')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	transition := func(from, to, event string) (bool, error) {
		tx, err := db.Begin()
		if err != nil {
			return false, err
		}
		defer tx.Rollback()
		result, err := tx.Exec(`UPDATE design_intent SET state=$1 WHERE id='one' AND state=$2`, to, from)
		if err != nil {
			return false, err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return false, err
		}
		if _, err = tx.Exec(`INSERT INTO design_audit VALUES ('one',$1)`, event); err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	state := func() string {
		var value string
		if err := db.QueryRow(`SELECT state FROM design_intent WHERE id='one'`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if ok, err := transition("prepared", "applying", "reject"); err == nil || ok || state() != "prepared" {
		t.Fatal("audit rejection must roll back claim")
	}
	var wg sync.WaitGroup
	var adCalls atomic.Int32
	results := make(chan bool, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := transition("prepared", "applying", "claimed")
			if ok && err == nil {
				adCalls.Add(1) // synthetic external side effect after durable claim only
			}
			results <- ok
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("claim winners: %d", winners)
	}
	// The one winning executor may now call AD. Simulate success followed by a DB audit failure.
	if ok, err := transition("applying", "succeeded", "reject"); err == nil || ok || state() != "applying" {
		t.Fatal("lost final audit must preserve uncertain state")
	}
	ok, err := transition("prepared", "applying", "claimed")
	if ok && err == nil {
		adCalls.Add(1)
	}
	if err != nil || ok {
		t.Fatal("restart must not reclaim an uncertain operation")
	}
	if adCalls.Load() != 1 {
		t.Fatal("AD operation replayed")
	}
	if ok, err := transition("applying", "reconciled_effect_observed", "reconciled"); err != nil || !ok {
		t.Fatal("explicit reconciliation failed")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM design_audit`).Scan(&count); err != nil || count != 2 {
		t.Fatal("unexpected durable evidence")
	}
}
