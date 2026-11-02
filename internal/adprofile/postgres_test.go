package adprofile

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPostgresProfileJournal(t *testing.T) {
	dsn := os.Getenv("IDENTITY_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL not configured")
	}
	u, e := url.Parse(dsn)
	if e != nil || u.Hostname() != "127.0.0.1" || u.Port() != "55441" || u.Path != "/postgres" {
		t.Fatal("disposable loopback database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal("test database unavailable")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("profile_test_%d", time.Now().UnixNano())
	id := pgx.Identifier{schema}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+id); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+id+" CASCADE")
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, e := sql.Open("pgx", u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(Schema); e != nil {
		t.Fatal(e)
	}
	s, f := fixture(t)
	s.Journal, e = NewJournal(db, []byte(strings.Repeat("k", 32)))
	if e != nil {
		t.Fatal(e)
	}
	r := prepare(t, s)
	_, e = db.Exec(`CREATE FUNCTION fail_profile_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event='succeeded' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_profile_audit BEFORE INSERT ON ad_profile_audit FOR EACH ROW EXECUTE FUNCTION fail_profile_audit()`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Handle(ctx, r); e != ErrUncertain {
		t.Fatal("lost final audit not reported uncertain", e)
	}
	s.Handle(ctx, r)
	if f.calls != 1 {
		t.Fatal("PostgreSQL operation replayed")
	}
	if e = s.Journal.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	r.Action = "reconcile"
	if response, e := s.Handle(ctx, r); e != nil || response.Operation.State != "reconciled_effect_observed" {
		t.Fatal("PostgreSQL reconciliation failed", e)
	}
}
