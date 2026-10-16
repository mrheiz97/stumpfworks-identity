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

type atomicBadgeStore interface {
	CreateUser(context.Context, string, string, string) (User, error)
	GetUser(context.Context, int64) (User, error)
	UserByUsername(context.Context, string) (User, error)
	CreateUserWithAudit(context.Context, string, string, string, string, string) (User, error)
	CreateBadge(context.Context, int64, string, string) (Badge, error)
	CreateBadgeWithAudit(context.Context, int64, string, string, string) (Badge, error)
	ReplaceBadgePendingWithAudit(context.Context, int64, string, string, string) (Badge, error)
	RevokeBadgeWithAudit(context.Context, int64, string) error
	ReplaceBadgePending(context.Context, int64, string, string) (Badge, error)
	GetBadge(context.Context, int64) (Badge, error)
	Audits(context.Context) ([]Audit, error)
	WriteAudit(context.Context, Audit) error
	RecordBadgeAuthenticationSuccess(context.Context, int64, string, string) error
	RevokeActiveBadgeForUserWithAudit(context.Context, int64, int64, string) (UserBadge, error)
	ActivatePendingBadgeForUserWithAudit(context.Context, int64, int64, string) error
	CreateOIDCClient(context.Context, string, string, string, string) error
	CreateOIDCClientWithAudit(context.Context, string, string, string, string, string) error
	RotateOIDCClientSecretWithAudit(context.Context, string, string, string) error
	UpdateOIDCClientConfigurationWithAudit(context.Context, string, string, string, string) error
	SetOIDCClientEnabledWithAudit(context.Context, string, bool, string) error
	ClientByID(context.Context, string) (Client, error)
	CreateClientWithAudit(context.Context, string, string, string) (Client, error)
	RotateClientTokenWithAudit(context.Context, string, string, string) error
	SetClientEnabledWithAudit(context.Context, string, bool, string) error
	OIDCClientByID(context.Context, string) (OIDCClient, error)
	EnsureOIDCSubjectWithAudit(context.Context, int64, string) (string, error)
	CreateOIDCCodeWithAudit(context.Context, OIDCCode, string, string) error
	OIDCCodeForExchange(context.Context, string, string, string, time.Time) (OIDCCode, error)
	ConsumeOIDCCodeWithAudit(context.Context, string, string, string, time.Time, string) (OIDCCode, error)
	SetUserPINWithAudit(context.Context, int64, string, string, string) error
	CreateSelfServiceSession(context.Context, string, string, time.Time) error
	CreateSelfServiceSessionWithAudit(context.Context, string, string, time.Time, string) error
	ActiveSelfServiceSession(context.Context, string, string, time.Time) (SelfServiceSession, error)
	RevokeOtherSelfServiceSessionsWithAudit(context.Context, string, string, string) (int64, error)
}

func TestSQLiteAtomicLostBadge(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testAtomicLostBadge(t, s, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_atomic_audit"
		if reject {
			query = "CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := s.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal("SQLite atomic audit fixture setup failed")
		}
	})
	testAtomicActivation(t, s, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_atomic_audit"
		if reject {
			query = "CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := s.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal("SQLite atomic audit fixture setup failed")
		}
	})
	testAtomicBadgeAuthentication(t, s, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_atomic_audit"
		if reject {
			query = "CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := s.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal("SQLite atomic audit fixture setup failed")
		}
	})
	testAtomicOIDCIssuance(t, s, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_atomic_audit"
		if reject {
			query = "CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := s.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal("SQLite atomic audit fixture setup failed")
		}
	})
	testAtomicSessionMutations(t, s, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_atomic_audit"
		if reject {
			query = "CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := s.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal("SQLite atomic audit fixture setup failed")
		}
	})
	testAtomicAdministrativeMutations(t, s, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_atomic_audit"
		if reject {
			query = "CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := s.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal("SQLite atomic audit fixture setup failed")
		}
	})
	testAtomicOIDCAdministration(t, s, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_atomic_audit"
		if reject {
			query = "CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := s.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal("SQLite atomic audit fixture setup failed")
		}
	})
	testAtomicClientAdministration(t, s, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_atomic_audit"
		if reject {
			query = "CREATE TRIGGER fail_atomic_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := s.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal("SQLite atomic audit fixture setup failed")
		}
	})
}

func testAtomicClientAdministration(t *testing.T, s atomicBadgeStore, rejectAudit func(bool)) {
	t.Helper()
	ctx := t.Context()
	rejectAudit(true)
	if _, err := s.CreateClientWithAudit(ctx, "atomic-greeter", "initial-hash", ""); err == nil {
		t.Fatal("client registration committed despite audit failure")
	}
	if _, err := s.ClientByID(ctx, "atomic-greeter"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("audit failure left a registered client")
	}
	rejectAudit(false)
	if _, err := s.CreateClientWithAudit(ctx, "atomic-greeter", "initial-hash", ""); err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if err := s.RotateClientTokenWithAudit(ctx, "atomic-greeter", "replacement-hash", ""); err == nil {
		t.Fatal("client token rotation committed despite audit failure")
	}
	client, err := s.ClientByID(ctx, "atomic-greeter")
	if err != nil || client.TokenHash != "initial-hash" {
		t.Fatal("audit failure changed the client token")
	}
	if err := s.SetClientEnabledWithAudit(ctx, "atomic-greeter", false, ""); err == nil {
		t.Fatal("client disable committed despite audit failure")
	}
	client, err = s.ClientByID(ctx, "atomic-greeter")
	if err != nil || !client.Enabled {
		t.Fatal("audit failure disabled the client")
	}
	rejectAudit(false)
	if err := s.RotateClientTokenWithAudit(ctx, "atomic-greeter", "replacement-hash", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientEnabledWithAudit(ctx, "atomic-greeter", false, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientEnabledWithAudit(ctx, "atomic-greeter", true, ""); err != nil {
		t.Fatal(err)
	}
	events, err := s.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"client_registered": 1, "client_token_rotated": 1, "client_disabled": 1, "client_enabled": 1}
	for _, event := range events {
		if event.ClientID == "atomic-greeter" {
			want[event.EventType]--
			if !event.Success || event.Details != "" {
				t.Fatal("client administration audit exposed unexpected detail")
			}
		}
	}
	for event, remaining := range want {
		if remaining != 0 {
			t.Fatalf("client administration audit %s lost or duplicated", event)
		}
	}
}

func testAtomicOIDCAdministration(t *testing.T, s atomicBadgeStore, rejectAudit func(bool)) {
	t.Helper()
	ctx := t.Context()
	rejectAudit(true)
	if err := s.CreateOIDCClientWithAudit(ctx, "admin-atomic-client", "initial-hash", "https://example.test/callback", "openid", ""); err == nil {
		t.Fatal("OIDC client creation committed despite audit failure")
	}
	if _, err := s.OIDCClientByID(ctx, "admin-atomic-client"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("audit failure left an OIDC client")
	}
	rejectAudit(false)
	if err := s.CreateOIDCClientWithAudit(ctx, "admin-atomic-client", "initial-hash", "https://example.test/callback", "openid", ""); err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if err := s.RotateOIDCClientSecretWithAudit(ctx, "admin-atomic-client", "replacement-hash", ""); err == nil {
		t.Fatal("OIDC secret rotation committed despite audit failure")
	}
	client, err := s.OIDCClientByID(ctx, "admin-atomic-client")
	if err != nil || client.SecretHash != "initial-hash" {
		t.Fatal("audit failure changed the OIDC client secret")
	}
	if err := s.UpdateOIDCClientConfigurationWithAudit(ctx, "admin-atomic-client", "https://changed.example.test/callback", "openid profile", ""); err == nil {
		t.Fatal("OIDC configuration update committed despite audit failure")
	}
	client, err = s.OIDCClientByID(ctx, "admin-atomic-client")
	if err != nil || client.RedirectURIs != "https://example.test/callback" || client.Scopes != "openid" {
		t.Fatal("audit failure changed the OIDC client configuration")
	}
	if err := s.SetOIDCClientEnabledWithAudit(ctx, "admin-atomic-client", false, ""); err == nil {
		t.Fatal("OIDC client disable committed despite audit failure")
	}
	client, err = s.OIDCClientByID(ctx, "admin-atomic-client")
	if err != nil || !client.Enabled {
		t.Fatal("audit failure disabled the OIDC client")
	}
	owner, err := s.CreateUser(ctx, "subject-atomic-owner", "Subject owner", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureOIDCSubjectWithAudit(ctx, owner.ID, ""); err == nil {
		t.Fatal("OIDC subject creation committed despite audit failure")
	}
	owner, err = s.GetUser(ctx, owner.ID)
	if err != nil || owner.OIDCSubject != "" {
		t.Fatal("audit failure left an OIDC subject")
	}
	rejectAudit(false)
	if err := s.RotateOIDCClientSecretWithAudit(ctx, "admin-atomic-client", "replacement-hash", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateOIDCClientConfigurationWithAudit(ctx, "admin-atomic-client", "https://first.example.test/callback\nhttps://second.example.test/callback", "openid profile", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOIDCClientEnabledWithAudit(ctx, "admin-atomic-client", false, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureOIDCSubjectWithAudit(ctx, owner.ID, ""); err != nil {
		t.Fatal(err)
	}
	client, err = s.OIDCClientByID(ctx, "admin-atomic-client")
	if err != nil || client.RedirectURIs != "https://first.example.test/callback\nhttps://second.example.test/callback" || client.Scopes != "openid profile" {
		t.Fatal("OIDC client configuration update was not committed")
	}
	events, err := s.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	configurationEvents := 0
	for _, event := range events {
		if event.EventType == "oidc_client_configuration_updated" && event.ClientID == "admin-atomic-client" && event.Success && event.Details == "" {
			configurationEvents++
		}
	}
	if configurationEvents != 1 {
		t.Fatalf("expected one safe OIDC configuration audit event, got %d", configurationEvents)
	}
}

func testAtomicAdministrativeMutations(t *testing.T, s atomicBadgeStore, rejectAudit func(bool)) {
	t.Helper()
	ctx := t.Context()
	rejectAudit(true)
	if _, err := s.CreateUserWithAudit(ctx, "admin-audit-owner", "Administrative audit owner", "", "user_created", "198.51.100.93"); err == nil {
		t.Fatal("user creation committed despite audit failure")
	}
	if _, err := s.UserByUsername(ctx, "admin-audit-owner"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("audit failure left a created user")
	}
	rejectAudit(false)
	owner, err := s.CreateUserWithAudit(ctx, "admin-audit-owner", "Administrative audit owner", "", "user_created", "198.51.100.93")
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if _, err := s.CreateBadgeWithAudit(ctx, owner.ID, "administrative-hash", "administrative badge", "198.51.100.93"); err == nil {
		t.Fatal("badge creation committed despite audit failure")
	}
	rejectAudit(false)
	badge, err := s.CreateBadgeWithAudit(ctx, owner.ID, "administrative-hash", "administrative badge", "198.51.100.93")
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if err := s.RevokeBadgeWithAudit(ctx, badge.ID, "198.51.100.93"); err == nil {
		t.Fatal("badge revocation committed despite audit failure")
	}
	if found, err := s.GetBadge(ctx, badge.ID); err != nil || !found.Enabled {
		t.Fatal("audit failure revoked the badge")
	}
	if _, err := s.ReplaceBadgePendingWithAudit(ctx, badge.ID, "replacement-hash", "replacement", "198.51.100.93"); err == nil {
		t.Fatal("badge replacement committed despite audit failure")
	}
	if found, err := s.GetBadge(ctx, badge.ID); err != nil || !found.Enabled {
		t.Fatal("audit failure replaced the badge")
	}
	rejectAudit(false)
	replacement, err := s.ReplaceBadgePendingWithAudit(ctx, badge.ID, "replacement-hash", "replacement", "198.51.100.93")
	if err != nil {
		t.Fatal(err)
	}
	if old, err := s.GetBadge(ctx, badge.ID); err != nil || old.Enabled || !replacement.ActivationPending || replacement.Enabled {
		t.Fatal("audited badge replacement state is invalid")
	}
}

func testAtomicSessionMutations(t *testing.T, s atomicBadgeStore, rejectAudit func(bool)) {
	t.Helper()
	ctx := t.Context()
	owner, err := s.CreateUser(ctx, "session-audit-owner", "Synthetic session owner", "")
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if err := s.SetUserPINWithAudit(ctx, owner.ID, "synthetic-pin-hash", "pin_self_service_changed", "198.51.100.92"); err == nil {
		t.Fatal("PIN change committed despite audit failure")
	}
	found, err := s.GetUser(ctx, owner.ID)
	if err != nil || found.PINHash != "" {
		t.Fatal("audit failure did not roll back PIN change")
	}
	expires := time.Now().UTC().Add(time.Hour)
	if err := s.CreateSelfServiceSessionWithAudit(ctx, "session-current", owner.Username, expires, "198.51.100.92"); err == nil {
		t.Fatal("session creation committed despite audit failure")
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "session-current", owner.Username, time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("audit failure left an active session")
	}
	rejectAudit(false)
	if err := s.SetUserPINWithAudit(ctx, owner.ID, "synthetic-pin-hash", "pin_self_service_changed", "198.51.100.92"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSelfServiceSessionWithAudit(ctx, "session-current", owner.Username, expires, "198.51.100.92"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSelfServiceSession(ctx, "session-other", owner.Username, expires); err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if _, err := s.RevokeOtherSelfServiceSessionsWithAudit(ctx, owner.Username, "session-current", "198.51.100.92"); err == nil {
		t.Fatal("session revocation committed despite audit failure")
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "session-other", owner.Username, time.Now()); err != nil {
		t.Fatal("audit failure revoked another session")
	}
	rejectAudit(false)
	count, err := s.RevokeOtherSelfServiceSessionsWithAudit(ctx, owner.Username, "session-current", "198.51.100.92")
	if err != nil || count != 1 {
		t.Fatal("audited session revocation failed")
	}
	if _, err := s.ActiveSelfServiceSession(ctx, "session-other", owner.Username, time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("audited session revocation did not persist")
	}
}

func testAtomicOIDCIssuance(t *testing.T, s atomicBadgeStore, rejectAudit func(bool)) {
	t.Helper()
	ctx := t.Context()
	owner, err := s.CreateUser(ctx, "oidc-audit-owner", "Synthetic OIDC owner", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOIDCClient(ctx, "oidc-audit-client", "synthetic-secret-hash", "https://example.test/callback", "openid profile"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	code := OIDCCode{CodeHash: "oidc-audit-code", ClientID: "oidc-audit-client", UserID: owner.ID, RedirectURI: "https://example.test/callback", Scope: "openid profile", Nonce: "synthetic-nonce", CodeChallenge: "synthetic-challenge", ExpiresAt: now.Add(time.Minute)}
	rejectAudit(true)
	if err := s.CreateOIDCCodeWithAudit(ctx, code, owner.Username, "198.51.100.91"); err == nil {
		t.Fatal("OIDC code committed despite audit failure")
	}
	if _, err := s.OIDCCodeForExchange(ctx, code.CodeHash, code.ClientID, code.RedirectURI, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("audit failure left a redeemable OIDC code")
	}
	rejectAudit(false)
	if err := s.CreateOIDCCodeWithAudit(ctx, code, owner.Username, "198.51.100.91"); err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if _, err := s.ConsumeOIDCCodeWithAudit(ctx, code.CodeHash, code.ClientID, code.RedirectURI, now, "198.51.100.91"); err == nil {
		t.Fatal("OIDC code consumption committed despite audit failure")
	}
	if _, err := s.OIDCCodeForExchange(ctx, code.CodeHash, code.ClientID, code.RedirectURI, now); err != nil {
		t.Fatal("audit failure consumed the OIDC code")
	}
	rejectAudit(false)
	if _, err := s.ConsumeOIDCCodeWithAudit(ctx, code.CodeHash, code.ClientID, code.RedirectURI, now, "198.51.100.91"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OIDCCodeForExchange(ctx, code.CodeHash, code.ClientID, code.RedirectURI, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("audited OIDC code remained redeemable")
	}
	events, err := s.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"oidc_login": 1, "oidc_consent": 1, "oidc_code_issued": 1, "oidc_token_issued": 1}
	for _, event := range events {
		if _, ok := want[event.EventType]; !ok || event.ClientID != code.ClientID {
			continue
		}
		if event.Username != owner.Username || !event.Success || event.IPAddress != "198.51.100.91" {
			t.Fatal("atomic OIDC audit identity changed")
		}
		want[event.EventType]--
	}
	for event, remaining := range want {
		if remaining != 0 {
			t.Fatalf("OIDC audit event %s lost or duplicated", event)
		}
	}
}

func testAtomicBadgeAuthentication(t *testing.T, s atomicBadgeStore, rejectAudit func(bool)) {
	t.Helper()
	ctx := t.Context()
	owner, err := s.CreateUser(ctx, "auth-audit-owner", "Synthetic auth owner", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateBadge(ctx, owner.ID, "synthetic-auth-hash", "auth fixture")
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if err := s.RecordBadgeAuthenticationSuccess(ctx, b.ID, "fixture-client", "198.51.100.90"); err == nil {
		t.Fatal("badge use committed despite audit failure")
	}
	found, err := s.GetBadge(ctx, b.ID)
	if err != nil || found.LastUsedAt.Valid {
		t.Fatal("audit failure did not roll back badge last-use marker")
	}
	rejectAudit(false)
	if err := s.RecordBadgeAuthenticationSuccess(ctx, b.ID, "fixture-client", "198.51.100.90"); err != nil {
		t.Fatal(err)
	}
	found, err = s.GetBadge(ctx, b.ID)
	if err != nil || !found.LastUsedAt.Valid {
		t.Fatal("audited badge use did not persist")
	}
	events, err := s.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, event := range events {
		if event.BadgeID == b.BadgeCode && event.EventType == "auth_success" {
			matched++
			if event.Username != owner.Username || event.ClientID != "fixture-client" || !event.Success || event.IPAddress != "198.51.100.90" || event.Details != "" {
				t.Fatal("atomic badge authentication audit identity changed")
			}
		}
	}
	if matched != 1 {
		t.Fatal("atomic badge authentication event lost or duplicated")
	}
}

func testAtomicActivation(t *testing.T, s atomicBadgeStore, rejectAudit func(bool)) {
	t.Helper()
	ctx := t.Context()
	owner, err := s.CreateUser(ctx, "activation-owner", "Synthetic activation owner", "")
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.CreateBadge(ctx, owner.ID, "synthetic-original-hash", "activation original")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.ReplaceBadgePending(ctx, original.ID, "synthetic-replacement-hash", "activation replacement")
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(true)
	if err := s.ActivatePendingBadgeForUserWithAudit(ctx, pending.ID, owner.ID, "198.51.100.88"); err == nil {
		t.Fatal("activation committed despite audit failure")
	}
	found, err := s.GetBadge(ctx, pending.ID)
	if err != nil || found.Enabled || !found.ActivationPending {
		t.Fatal("audit failure did not roll back activation")
	}
	rejectAudit(false)
	if err := s.ActivatePendingBadgeForUserWithAudit(ctx, pending.ID, owner.ID, "198.51.100.88"); err != nil {
		t.Fatal(err)
	}
	found, err = s.GetBadge(ctx, pending.ID)
	if err != nil || !found.Enabled || found.ActivationPending {
		t.Fatal("audited activation did not persist")
	}
	events, err := s.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, event := range events {
		if event.BadgeID == pending.BadgeCode && event.EventType == "badge_self_service_activated" {
			matched++
			if event.Username != owner.Username || !event.Success || event.IPAddress != "198.51.100.88" || event.Details != "replacement_badge" {
				t.Fatal("atomic activation audit identity changed")
			}
		}
	}
	if matched != 1 {
		t.Fatal("atomic activation audit event lost or duplicated")
	}
}

func testAtomicLostBadge(t *testing.T, s atomicBadgeStore, rejectAudit func(bool)) {
	t.Helper()
	ctx := t.Context()
	owner, err := s.CreateUser(ctx, "atomic-owner", "Synthetic atomic owner", "")
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := s.CreateUser(ctx, "atomic-stranger", "Synthetic atomic stranger", "")
	if err != nil {
		t.Fatal(err)
	}
	badge, err := s.CreateBadge(ctx, owner.ID, "synthetic-atomic-token-hash", "atomic fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeActiveBadgeForUserWithAudit(ctx, badge.ID, stranger.ID, ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("foreign audited revocation accepted")
	}
	if _, err := s.RevokeActiveBadgeForUserWithAudit(ctx, badge.ID, owner.ID, "not-an-IP"); err == nil {
		t.Fatal("invalid peer IP accepted")
	}
	rejectAudit(true)
	defer rejectAudit(false)
	if err := s.WriteAudit(ctx, Audit{EventType: "synthetic_rejected"}); err == nil {
		t.Fatal("standalone audit error swallowed")
	}
	if _, err := s.RevokeActiveBadgeForUserWithAudit(ctx, badge.ID, owner.ID, ""); err == nil {
		t.Fatal("revocation committed despite audit failure")
	}
	if found, err := s.GetBadge(ctx, badge.ID); err != nil || !found.Enabled || found.RevokedAt.Valid {
		t.Fatal("audit failure did not roll back badge")
	}
	rejectAudit(false)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.RevokeActiveBadgeForUserWithAudit(ctx, badge.ID, owner.ID, "198.51.100.77")
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, sql.ErrNoRows) {
				t.Error("unexpected competing audited revocation error")
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("audited revocation did not have one winner")
	}
	events, err := s.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, event := range events {
		if event.BadgeID != badge.BadgeCode {
			continue
		}
		matched++
		if event.EventType != "badge_self_service_revoked" || event.Username != owner.Username || !event.Success || event.IPAddress != "198.51.100.77" || event.Details != "lost_badge" {
			t.Fatal("atomic event identity changed")
		}
	}
	if matched != 1 {
		t.Fatal("atomic audit event lost or duplicated")
	}
	if found, err := s.GetBadge(ctx, badge.ID); err != nil || found.Enabled || !found.RevokedAt.Valid {
		t.Fatal("audited revoke did not persist")
	}
}
