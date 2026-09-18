package database

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"
)

func TestPostgresAdapterInvalidDependencies(t *testing.T) {
	if _, err := NewPostgresStore(nil); err == nil {
		t.Fatal("nil pool accepted")
	}
	if err := MigratePostgres(context.Background(), nil); err == nil {
		t.Fatal("nil migration pool accepted")
	}
	s := &PostgresStore{}
	for _, limit := range []int64{0, -1, 1000001} {
		if _, err := s.ImportSQLite(context.Background(), nil, limit); err == nil {
			t.Fatal("invalid import dependencies accepted")
		}
	}
	if _, err := normalizeSQLiteValue(42, "timestamp with time zone"); err == nil {
		t.Fatal("invalid timestamp type accepted")
	}
	if value, err := normalizeSQLiteValue(nil, "boolean"); err != nil || value != nil {
		t.Fatal("nullable value changed")
	}
	if err := hashImportRow(sha256.New(), []any{make(chan int)}); err == nil {
		t.Fatal("unsupported field representation accepted")
	}
}

func TestSQLiteImportValueNormalization(t *testing.T) {
	for _, value := range []any{int64(2), "true", 1.0} {
		if _, err := normalizeSQLiteValue(value, "boolean"); err == nil {
			t.Fatal("invalid SQLite bool accepted")
		}
	}
	for _, value := range []any{int64(0), int64(1), true, false} {
		if _, err := normalizeSQLiteValue(value, "boolean"); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []any{"2026-01-02 03:04:05", "2026-01-02T04:04:05+01:00", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} {
		normalized, err := normalizeSQLiteValue(value, "timestamp with time zone")
		if err != nil {
			t.Fatal(err)
		}
		if !normalized.(time.Time).Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
			t.Fatal("timestamp changed instant")
		}
	}
	if _, err := normalizeSQLiteValue("not-a-date", "timestamp with time zone"); err == nil {
		t.Fatal("invalid date accepted")
	}
}
