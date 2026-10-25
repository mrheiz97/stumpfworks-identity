package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestOpenUpgradesExistingClientTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE clients (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL, version TEXT NOT NULL DEFAULT '', network_status TEXT NOT NULL DEFAULT 'unknown', ad_status TEXT NOT NULL DEFAULT 'unknown', camera_status TEXT NOT NULL DEFAULT 'unknown', kerberos_status TEXT NOT NULL DEFAULT 'unknown', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen_at DATETIME); INSERT INTO clients(client_id,token_hash) VALUES('legacy','hash')`)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	c, err := store.ClientByID(context.Background(), "legacy")
	if err != nil || !c.Enabled {
		t.Fatalf("legacy client was not enabled after migration: %+v, %v", c, err)
	}
}

func TestOpenBackfillsStableWebAuthnManagementID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-webauthn.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL,directory_dn TEXT NOT NULL DEFAULT '',pin_hash TEXT NOT NULL DEFAULT '',oidc_subject TEXT NOT NULL DEFAULT '',created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE webauthn_users (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,user_handle BLOB NOT NULL UNIQUE,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE webauthn_credentials (credential_id BLOB PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES webauthn_users(user_id) ON DELETE CASCADE,public_key BLOB NOT NULL,rp_id TEXT NOT NULL,name TEXT NOT NULL,transports TEXT NOT NULL DEFAULT '',attestation_type TEXT NOT NULL DEFAULT '',attestation_format TEXT NOT NULL DEFAULT '',flags INTEGER NOT NULL DEFAULT 0,sign_count INTEGER NOT NULL DEFAULT 0,backup_eligible BOOLEAN NOT NULL DEFAULT 0,backup_state BOOLEAN NOT NULL DEFAULT 0,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,last_used_at DATETIME,revoked_at DATETIME);
INSERT INTO users(id,username,display_name) VALUES(1,'legacy-passkey','Legacy Passkey');
INSERT INTO webauthn_users(user_id,user_handle) VALUES(1,x'3031323334353637383930313233343536373839303132333435363738393031');
INSERT INTO webauthn_credentials(credential_id,user_id,public_key,rp_id,name) VALUES(x'010203',1,x'040506','login.example.test','Legacy key')`)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := store.WebAuthnCredentialsByUser(t.Context(), 1)
	if err != nil || len(credentials) != 1 || len(credentials[0].ManagementID) < 16 {
		t.Fatalf("legacy management ID missing: %+v, %v", credentials, err)
	}
	managementID := credentials[0].ManagementID
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	credentials, err = store.WebAuthnCredentialsByUser(t.Context(), 1)
	if err != nil || len(credentials) != 1 || credentials[0].ManagementID != managementID {
		t.Fatal("management ID changed after reopen")
	}
	if _, err = store.DB.ExecContext(t.Context(), `UPDATE webauthn_credentials SET management_id='' WHERE credential_id=?`, []byte{1, 2, 3}); err == nil {
		t.Fatal("upgraded SQLite accepted an invalid management ID")
	}
}

func TestOIDCSubjectAndClientSafety(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.CreateUser(t.Context(), "alice", "Alice", "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.EnsureOIDCSubject(t.Context(), u.ID)
	if err != nil || first == "" || first == "alice" {
		t.Fatalf("bad subject %q: %v", first, err)
	}
	if _, err = s.DB.Exec(`UPDATE users SET username='alice-renamed' WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	second, err := s.EnsureOIDCSubject(t.Context(), u.ID)
	if err != nil || second != first {
		t.Fatalf("subject changed: %q %q %v", first, second, err)
	}
	if err = s.CreateOIDCClient(t.Context(), "access", "first-hash", "https://access.test/callback", "openid"); err != nil {
		t.Fatal(err)
	}
	if err = s.CreateOIDCClient(t.Context(), "access", "second-hash", "https://evil.test/callback", "openid"); err == nil {
		t.Fatal("duplicate client silently overwritten")
	}
	c, err := s.OIDCClientByID(t.Context(), "access")
	if err != nil || c.SecretHash != "first-hash" || c.RedirectURIs != "https://access.test/callback" {
		t.Fatalf("client changed: %+v %v", c, err)
	}
}

func TestClientUpdateMetadata(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.CreateClient(t.Context(), "client01", "hash"); err != nil {
		t.Fatal(err)
	}
	updatedAt := time.Now().UTC().Truncate(time.Second)
	update := &ClientUpdate{Version: "1.2.0", Status: "success", UpdatedAt: updatedAt, RollbackAvailable: true}
	if err = store.UpdateClientStatusWithUpdate(t.Context(), "client01", "1.2.0", "ok", "ok", "ok", "ok", update); err != nil {
		t.Fatal(err)
	}
	client, err := store.ClientByID(t.Context(), "client01")
	if err != nil || client.LastUpdateVersion != "1.2.0" || client.LastUpdateStatus != "success" || client.LastUpdateAt == nil || !client.RollbackAvailable {
		t.Fatalf("unexpected update metadata: %+v, %v", client, err)
	}
}

func TestRotateAndDisableClient(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.CreateClient(t.Context(), "client01", "old"); err != nil {
		t.Fatal(err)
	}
	if err = store.RotateClientToken(t.Context(), "client01", "new"); err != nil {
		t.Fatal(err)
	}
	if err = store.SetClientEnabled(t.Context(), "client01", false); err != nil {
		t.Fatal(err)
	}
	c, err := store.ClientByID(t.Context(), "client01")
	if err != nil || c.TokenHash != "new" || c.Enabled {
		t.Fatalf("unexpected client state: %+v, %v", c, err)
	}
}

func TestActiveBadgesByUserIsIsolatedAndSecretFree(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	alice, _ := store.CreateUser(t.Context(), "alice", "Alice", "")
	bob, _ := store.CreateUser(t.Context(), "bob", "Bob", "")
	active, _ := store.CreateBadge(t.Context(), alice.ID, "alice-secret", "Primary")
	revoked, _ := store.CreateBadge(t.Context(), alice.ID, "revoked-secret", "Old")
	_, _ = store.CreateBadge(t.Context(), bob.ID, "bob-secret", "Bob badge")
	if err = store.Revoke(t.Context(), revoked.ID); err != nil {
		t.Fatal(err)
	}
	badges, err := store.ActiveBadgesByUser(t.Context(), alice.ID)
	if err != nil || len(badges) != 1 || badges[0].BadgeCode != active.BadgeCode || badges[0].Description != "Primary" {
		t.Fatalf("unexpected active badges: %+v, %v", badges, err)
	}
}

func TestRevokeActiveBadgeForUserEnforcesOwnership(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	alice, _ := store.CreateUser(t.Context(), "alice", "Alice", "")
	bob, _ := store.CreateUser(t.Context(), "bob", "Bob", "")
	badge, _ := store.CreateBadge(t.Context(), alice.ID, "secret", "Primary")
	if _, err = store.RevokeActiveBadgeForUser(t.Context(), badge.ID, bob.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign badge revoke returned %v", err)
	}
	current, _ := store.GetBadge(t.Context(), badge.ID)
	if !current.Enabled {
		t.Fatal("foreign user revoked badge")
	}
	revoked, err := store.RevokeActiveBadgeForUser(t.Context(), badge.ID, alice.ID)
	if err != nil || revoked.BadgeCode != badge.BadgeCode {
		t.Fatalf("owner revoke failed: %+v, %v", revoked, err)
	}
	if _, err = store.RevokeActiveBadgeForUser(t.Context(), badge.ID, alice.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second revoke returned %v", err)
	}
}

func TestRecentBadgeAuthByUserIsBoundedAndPrivate(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for i := 0; i < 25; i++ {
		store.Audit(t.Context(), "auth_success", "ALICE-BADGE", "Alice", "client-alice", true, "192.0.2.10", "private-detail")
	}
	store.Audit(t.Context(), "auth_failed", "BOB-BADGE", "bob", "client-bob", false, "192.0.2.11", "private-bob-detail")
	store.Audit(t.Context(), "self_service_login", "", "alice", "", true, "192.0.2.12", "not-a-badge-login")
	events, err := store.RecentBadgeAuthByUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 20 {
		t.Fatalf("expected bounded history of 20 entries, got %d", len(events))
	}
	for _, event := range events {
		if event.BadgeID != "ALICE-BADGE" || event.ClientID != "client-alice" || !event.Success {
			t.Fatalf("foreign or unrelated event leaked: %+v", event)
		}
	}
}

func TestPendingReplacementRequiresOwnerActivation(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	alice, _ := store.CreateUser(t.Context(), "alice", "Alice", "")
	bob, _ := store.CreateUser(t.Context(), "bob", "Bob", "")
	old, _ := store.CreateBadge(t.Context(), alice.ID, "old-hash", "Old")
	replacement, err := store.ReplaceBadgePending(t.Context(), old.ID, "new-hash", "Replacement")
	if err != nil || replacement.Enabled || !replacement.ActivationPending {
		t.Fatalf("unexpected pending replacement: %+v, %v", replacement, err)
	}
	if err = store.ActivatePendingBadgeForUser(t.Context(), replacement.ID, bob.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign activation returned %v", err)
	}
	if err = store.ActivatePendingBadgeForUser(t.Context(), replacement.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if err = store.ActivatePendingBadgeForUser(t.Context(), replacement.ID, alice.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second activation returned %v", err)
	}
}

func TestSelfServiceSessionsCanRevokeOthers(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Second)
	for _, id := range []string{"current", "other"} {
		if err = store.CreateSelfServiceSession(t.Context(), id, "alice", now.Add(15*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.CreateSelfServiceSession(t.Context(), "bob", "bob", now.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	count, err := store.RevokeOtherSelfServiceSessions(t.Context(), "alice", "current")
	if err != nil || count != 1 {
		t.Fatalf("unexpected revoke result: %d, %v", count, err)
	}
	if _, err = store.ActiveSelfServiceSession(t.Context(), "other", "alice", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("other session still active: %v", err)
	}
	if _, err = store.ActiveSelfServiceSession(t.Context(), "current", "alice", now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActiveSelfServiceSession(t.Context(), "bob", "bob", now); err != nil {
		t.Fatal(err)
	}
}
