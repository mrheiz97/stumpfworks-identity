package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type clientStore interface {
	CreateClient(context.Context, string, string) (Client, error)
	ClientByID(context.Context, string) (Client, error)
	Clients(context.Context) ([]Client, error)
	UpdateClientStatus(context.Context, string, string, string, string, string, string) error
	UpdateClientStatusWithUpdate(context.Context, string, string, string, string, string, string, *ClientUpdate) error
	RotateClientToken(context.Context, string, string) error
	SetClientEnabled(context.Context, string, bool) error
}

func TestSQLiteClientContract(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testClientContract(t, s)
}

func testClientContract(t *testing.T, s clientStore) {
	t.Helper()
	ctx := t.Context()
	const id = "contract-greeter"
	client, err := s.CreateClient(ctx, id, "synthetic-greeter-token")
	if err != nil || !client.Enabled || client.LastSeenAt != nil || client.LastUpdateAt != nil {
		t.Fatal("client defaults changed")
	}
	if _, err := s.CreateClient(ctx, id, "duplicate-token"); err == nil {
		t.Fatal("duplicate greeter accepted")
	}
	update := &ClientUpdate{Version: "fixture-v2", Status: "applied", UpdatedAt: time.Now().UTC().Truncate(time.Second), RollbackAvailable: true}
	if err := s.UpdateClientStatusWithUpdate(ctx, id, "fixture-v2", "up", "up", "up", "up", update); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateClientStatus(ctx, id, "fixture-v3", "up", "unknown", "up", "up"); err != nil {
		t.Fatal(err)
	}
	found, err := s.ClientByID(ctx, id)
	if err != nil || found.Version != "fixture-v3" || found.LastSeenAt == nil || found.LastUpdateAt == nil || !found.LastUpdateAt.Equal(update.UpdatedAt) || found.LastUpdateVersion != update.Version || !found.RollbackAvailable {
		t.Fatal("status heartbeat lost update metadata")
	}
	if err := s.SetClientEnabled(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateClientToken(ctx, id, "synthetic-rotated-token"); err != nil {
		t.Fatal(err)
	}
	found, err = s.ClientByID(ctx, id)
	if err != nil || found.Enabled || found.TokenHash != "synthetic-rotated-token" || found.Version != "fixture-v3" {
		t.Fatal("client rotation changed policy/metadata")
	}
	if clients, err := s.Clients(ctx); err != nil || len(clients) == 0 {
		t.Fatal("client listing failed")
	}
	for _, operation := range []func() error{
		func() error { return s.SetClientEnabled(ctx, "missing-greeter", false) },
		func() error { return s.RotateClientToken(ctx, "missing-greeter", "unused") },
		func() error { return s.UpdateClientStatus(ctx, "missing-greeter", "v1", "up", "up", "up", "up") },
		func() error {
			return s.UpdateClientStatusWithUpdate(ctx, "missing-greeter", "v1", "up", "up", "up", "up", update)
		},
	} {
		if err := operation(); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("missing client operation accepted")
		}
	}
}
