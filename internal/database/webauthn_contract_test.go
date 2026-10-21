package database

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type webAuthnFoundationStore interface {
	EnsureWebAuthnUserHandle(context.Context, int64) ([]byte, error)
	CreateWebAuthnCeremony(context.Context, WebAuthnCeremony) error
	ConsumeWebAuthnCeremony(context.Context, string, string, string, time.Time) (WebAuthnCeremony, error)
}

func testWebAuthnFoundationContract(t *testing.T, store webAuthnFoundationStore, userID int64) {
	t.Helper()
	ctx := t.Context()
	handle, err := store.EnsureWebAuthnUserHandle(ctx, userID)
	if err != nil || len(handle) != webAuthnHandleBytes {
		t.Fatalf("WebAuthn handle creation failed: %v", err)
	}
	again, err := store.EnsureWebAuthnUserHandle(ctx, userID)
	if err != nil || string(again) != string(handle) {
		t.Fatal("WebAuthn user handle was not stable")
	}
	now := time.Now().UTC()
	ceremony := WebAuthnCeremony{ID: "contract-ceremony", Kind: "authentication", Audience: "self-service", SessionData: []byte(`{"challenge":"synthetic"}`), CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	if err := store.CreateWebAuthnCeremony(ctx, ceremony); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeWebAuthnCeremony(ctx, ceremony.ID, ceremony.Kind, "admin", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("ceremony crossed audience")
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumed, err := store.ConsumeWebAuthnCeremony(ctx, ceremony.ID, ceremony.Kind, ceremony.Audience, now.Add(time.Second))
			if err == nil {
				winners.Add(1)
				if string(consumed.SessionData) != string(ceremony.SessionData) || !consumed.ConsumedAt.Valid {
					t.Error("consumed ceremony changed")
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				t.Errorf("unexpected ceremony consumption error: %v", err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("ceremony winners=%d, want 1", winners.Load())
	}
	expired := WebAuthnCeremony{ID: "expired-ceremony", Kind: "registration", Audience: "self-service", UserID: sql.NullInt64{Int64: userID, Valid: true}, SessionData: []byte(`{"challenge":"expired"}`), CreatedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(-time.Minute)}
	if err := store.CreateWebAuthnCeremony(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeWebAuthnCeremony(ctx, expired.ID, expired.Kind, expired.Audience, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("expired WebAuthn ceremony accepted")
	}
	invalid := ceremony
	invalid.ID = "invalid-ceremony"
	invalid.Kind = "unknown"
	if err := store.CreateWebAuthnCeremony(ctx, invalid); err == nil {
		t.Fatal("invalid WebAuthn ceremony accepted")
	}
}

func TestSQLiteWebAuthnFoundation(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	user, err := store.CreateUser(t.Context(), "passkey-user", "Passkey User", "")
	if err != nil {
		t.Fatal(err)
	}
	testWebAuthnFoundationContract(t, store, user.ID)
}
