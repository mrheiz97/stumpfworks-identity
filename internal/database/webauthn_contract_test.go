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
	WebAuthnUserByHandle(context.Context, []byte) (User, error)
	WebAuthnCredentialsByUser(context.Context, int64) ([]WebAuthnCredential, error)
	CompleteWebAuthnRegistration(context.Context, string, string, time.Time, WebAuthnCredential, string, string) error
	Audits(context.Context) ([]Audit, error)
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
	user, err := store.WebAuthnUserByHandle(ctx, handle)
	if err != nil || user.ID != userID {
		t.Fatalf("opaque WebAuthn handle lookup failed: %v", err)
	}
	if _, err := store.WebAuthnUserByHandle(ctx, []byte("short")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("invalid WebAuthn handle accepted")
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
	registration := WebAuthnCeremony{ID: "registration-ceremony", Kind: "registration", Audience: "self-service", UserID: sql.NullInt64{Int64: userID, Valid: true}, SessionData: []byte(`{"challenge":"register"}`), CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	if err := store.CreateWebAuthnCeremony(ctx, registration); err != nil {
		t.Fatal(err)
	}
	credential := WebAuthnCredential{CredentialID: []byte("synthetic-credential-id"), UserID: userID, PublicKey: []byte("synthetic-cose-public-key"), RPID: "login.example.test", Name: "Security key", Transports: "usb,internal", AttestationType: "none", AttestationFormat: "none", Flags: 5, SignCount: 7, BackupEligible: true, BackupState: true, CreatedAt: now}
	if err := store.CompleteWebAuthnRegistration(ctx, registration.ID, "admin", now, credential, user.Username, "192.0.2.10"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("registration ceremony crossed audience")
	}
	wrongUser := credential
	wrongUser.UserID++
	if err := store.CompleteWebAuthnRegistration(ctx, registration.ID, registration.Audience, now, wrongUser, user.Username, "192.0.2.10"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("registration ceremony crossed user binding")
	}
	if err := store.CompleteWebAuthnRegistration(ctx, registration.ID, registration.Audience, now, credential, "another-user", "192.0.2.10"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("registration audit accepted mismatched username")
	}
	if err := store.CompleteWebAuthnRegistration(ctx, registration.ID, registration.Audience, now, credential, user.Username, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	credentials, err := store.WebAuthnCredentialsByUser(ctx, userID)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("registered WebAuthn credential missing: %v", err)
	}
	stored := credentials[0]
	if string(stored.CredentialID) != string(credential.CredentialID) || string(stored.PublicKey) != string(credential.PublicKey) || stored.RPID != credential.RPID || stored.Name != credential.Name || stored.Transports != credential.Transports || stored.AttestationType != credential.AttestationType || stored.AttestationFormat != credential.AttestationFormat || stored.Flags != credential.Flags || stored.SignCount != credential.SignCount || !stored.BackupEligible || !stored.BackupState {
		t.Fatal("registered WebAuthn credential changed")
	}
	if err := store.CompleteWebAuthnRegistration(ctx, registration.ID, registration.Audience, now, credential, user.Username, "192.0.2.10"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("registration ceremony replay accepted")
	}
	audits, err := store.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var registrationAudits int
	for _, audit := range audits {
		if audit.EventType == "passkey_registered" {
			registrationAudits++
			if audit.Username != user.Username || !audit.Success || audit.IPAddress != "192.0.2.10" || audit.Details != "" {
				t.Fatal("Passkey audit exposed or changed data")
			}
		}
	}
	if registrationAudits != 1 {
		t.Fatalf("Passkey registration audit count=%d, want 1", registrationAudits)
	}
}

func testAtomicWebAuthnRegistration(t *testing.T, store webAuthnFoundationStore, user User, setAuditFailure func(bool)) {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC()
	ceremony := WebAuthnCeremony{ID: "registration-audit-failure", Kind: "registration", Audience: "self-service", UserID: sql.NullInt64{Int64: user.ID, Valid: true}, SessionData: []byte(`{"challenge":"audit"}`), CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	if err := store.CreateWebAuthnCeremony(ctx, ceremony); err != nil {
		t.Fatal(err)
	}
	credential := WebAuthnCredential{CredentialID: []byte("audit-failure-credential"), UserID: user.ID, PublicKey: []byte("audit-failure-public-key"), RPID: "login.example.test", Name: "Audit test", AttestationType: "none", AttestationFormat: "none", Flags: 5, CreatedAt: now}
	setAuditFailure(true)
	if err := store.CompleteWebAuthnRegistration(ctx, ceremony.ID, ceremony.Audience, now, credential, user.Username, "192.0.2.20"); err == nil {
		t.Fatal("WebAuthn registration survived audit failure")
	}
	setAuditFailure(false)
	credentials, err := store.WebAuthnCredentialsByUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, stored := range credentials {
		if string(stored.CredentialID) == string(credential.CredentialID) {
			t.Fatal("credential committed despite audit failure")
		}
	}
	if err := store.CompleteWebAuthnRegistration(ctx, ceremony.ID, ceremony.Audience, now, credential, user.Username, "192.0.2.20"); err != nil {
		t.Fatal("audit failure consumed registration ceremony")
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
	testAtomicWebAuthnRegistration(t, store, user, func(reject bool) {
		query := "DROP TRIGGER IF EXISTS fail_webauthn_audit"
		if reject {
			query = "CREATE TRIGGER fail_webauthn_audit BEFORE INSERT ON audit_log WHEN NEW.event_type='passkey_registered' BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END"
		}
		if _, err := store.DB.ExecContext(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	})
}
