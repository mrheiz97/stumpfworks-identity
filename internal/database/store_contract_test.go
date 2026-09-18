package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type sessionOIDCStore interface {
	CreateUser(context.Context, string, string, string) (User, error)
	GetUser(context.Context, int64) (User, error)
	UserByUsername(context.Context, string) (User, error)
	Users(context.Context) ([]User, error)
	SetUserPIN(context.Context, int64, string) error
	CreateOIDCClient(context.Context, string, string, string, string) error
	UpsertOIDCClient(context.Context, string, string, string, string) error
	RotateOIDCClientSecret(context.Context, string, string) error
	SetOIDCClientEnabled(context.Context, string, bool) error
	OIDCClientByID(context.Context, string) (OIDCClient, error)
	CreateSelfServiceSession(context.Context, string, string, time.Time) error
	ActiveSelfServiceSession(context.Context, string, string, time.Time) (SelfServiceSession, error)
	ActiveSelfServiceSessions(context.Context, string, time.Time) ([]SelfServiceSession, error)
	RevokeOtherSelfServiceSessions(context.Context, string, string) (int64, error)
	RevokeSelfServiceSession(context.Context, string, string) error
}

func TestSQLiteSessionOIDCContract(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testSessionOIDCContract(t, s)
}

func testSessionOIDCContract(t *testing.T, s sessionOIDCStore) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	user, err := s.CreateUser(ctx, "contract-user", "Synthetic contract", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserPIN(ctx, user.ID, "synthetic-contract-pin"); err != nil {
		t.Fatal(err)
	}
	found, err := s.GetUser(ctx, user.ID)
	if err != nil || !found.PINEnabled || found.PINHash != "synthetic-contract-pin" {
		t.Fatal("PIN roundtrip failed")
	}
	if err := s.SetUserPIN(ctx, 999999999, "unused"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("missing PIN user accepted")
	}
	if users, err := s.Users(ctx); err != nil || len(users) == 0 {
		t.Fatal("user list failed")
	}
	const clientID = "contract-oidc-app"
	if err := s.CreateOIDCClient(ctx, clientID, "synthetic-old-secret", "https://example.test/callback", "openid"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOIDCClient(ctx, clientID, "replacement", "https://wrong.test/", "openid"); err == nil {
		t.Fatal("duplicate client accepted")
	}
	if err := s.SetOIDCClientEnabled(ctx, clientID, false); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateOIDCClientSecret(ctx, clientID, "synthetic-new-secret"); err != nil {
		t.Fatal(err)
	}
	client, err := s.OIDCClientByID(ctx, clientID)
	if err != nil || client.Enabled || client.SecretHash != "synthetic-new-secret" || client.RedirectURIs != "https://example.test/callback" {
		t.Fatal("rotation changed client policy")
	}
	if err := s.RotateOIDCClientSecret(ctx, "missing-contract-client", "unused"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("missing rotation client accepted")
	}
	if err := s.SetOIDCClientEnabled(ctx, "missing-contract-client", false); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("missing enable client accepted")
	}
	if err := s.UpsertOIDCClient(ctx, clientID, "synthetic-upsert-secret", "https://example.test/new-callback", "openid profile"); err != nil {
		t.Fatal(err)
	}
	client, err = s.OIDCClientByID(ctx, clientID)
	if err != nil || !client.Enabled || client.SecretHash != "synthetic-upsert-secret" || client.Scopes != "openid profile" {
		t.Fatal("explicit upsert contract changed")
	}
	now := time.Now().UTC()
	for _, id := range []string{"contract-current", "contract-other"} {
		if err := s.CreateSelfServiceSession(ctx, id, "Contract-User", now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateSelfServiceSession(ctx, "contract-expired", "Contract-User", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSelfServiceSession(ctx, "contract-stranger", "other-user", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "contract-current", "CONTRACT-USER", now); err != nil {
		t.Fatal("case-normalized session lookup failed")
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "contract-current", "other-user", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("session owner isolation failed")
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "contract-expired", "contract-user", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("expired session accepted")
	}
	if sessions, err := s.ActiveSelfServiceSessions(ctx, "contract-user", now); err != nil || len(sessions) != 2 {
		t.Fatal("active session filtering failed")
	}
	if err := s.RevokeSelfServiceSession(ctx, "contract-current", "other-user"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "contract-current", "contract-user", now); err != nil {
		t.Fatal("stranger revoked session")
	}
	if count, err := s.RevokeOtherSelfServiceSessions(ctx, "CONTRACT-USER", "contract-current"); err != nil || count != 1 {
		t.Fatal("other-session revocation failed")
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "contract-other", "contract-user", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("revoked session accepted")
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "contract-stranger", "other-user", now); err != nil {
		t.Fatal("other-session revocation crossed owners")
	}
	if err := s.RevokeSelfServiceSession(ctx, "contract-current", "contract-user"); err != nil {
		t.Fatal(err)
	}
	if sessions, err := s.ActiveSelfServiceSessions(ctx, "contract-user", now); err != nil || len(sessions) != 0 {
		t.Fatal("revoked sessions still listed")
	}
	unicodeUser, err := s.CreateUser(ctx, "ä-contract-user", "Synthetic Unicode fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	if found, err := s.UserByUsername(ctx, "ä-CONTRACT-USER"); err != nil || found.ID != unicodeUser.ID {
		t.Fatal("ASCII username folding changed")
	}
	if _, err := s.UserByUsername(ctx, "Ä-CONTRACT-USER"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("Unicode username folding widened legacy identity matching")
	}
}
