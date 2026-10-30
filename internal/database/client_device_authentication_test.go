package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

type clientDeviceAuthenticationStore interface {
	CreateClient(context.Context, string, string) (Client, error)
	ClientByID(context.Context, string) (Client, error)
	CreateClientEnrollmentTokenWithAudit(context.Context, ClientEnrollmentToken, string) error
	EnrollClientDeviceCredentialWithAudit(context.Context, string, time.Time, ClientDeviceCredential, string) error
	RenewClientDeviceCredentialWithAudit(context.Context, string, time.Time, ClientDeviceCredential, string) error
	ClientDeviceCredentials(context.Context, string) ([]ClientDeviceCredential, error)
	ActiveClientDeviceCredential(context.Context, string, time.Time) (ClientDeviceCredential, error)
	RevokeClientDeviceCredentialWithAudit(context.Context, string, string, string, time.Time) error
	SetClientAuthenticationModeWithAudit(context.Context, string, string, string, time.Time) error
}

func TestSQLiteClientDeviceAuthenticationContract(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	testClientDeviceAuthenticationContract(t, store)
}

func TestSQLiteClientDeviceConcurrentRenewal(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	testClientDeviceConcurrentRenewal(t, store)
}

func testClientDeviceConcurrentRenewal(t *testing.T, store clientDeviceAuthenticationStore) {
	t.Helper()
	ctx := t.Context()
	const clientID = "concurrent-renewal-client"
	if _, err := store.CreateClient(ctx, clientID, "synthetic-status-token"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tokenHash := strings.Repeat("8", 64)
	token := ClientEnrollmentToken{ID: "concurrent-renewal-token", ClientID: clientID, TokenHash: tokenHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateClientEnrollmentTokenWithAudit(ctx, token, "192.0.2.60"); err != nil {
		t.Fatal(err)
	}
	current := ClientDeviceCredential{ID: "concurrent-renewal-current", ClientID: clientID, FingerprintSHA256: strings.Repeat("9", 64), Serial: "7ab", URISAN: "urn:stumpfworks:identity:client:" + clientID, PublicKeyAlgorithm: "ECDSA-P256", IssuerID: "stumpfworks-device-ca-01", IssuedAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour)}
	if err := store.EnrollClientDeviceCredentialWithAudit(ctx, tokenHash, now.Add(time.Second), current, "192.0.2.60"); err != nil {
		t.Fatal(err)
	}
	first, second := current, current
	first.ID, first.FingerprintSHA256, first.Serial = "concurrent-replacement-a", strings.Repeat("c", 64), "8ab"
	second.ID, second.FingerprintSHA256, second.Serial = "concurrent-replacement-b", strings.Repeat("e", 64), "9ab"
	first.IssuedAt, second.IssuedAt = now.Add(2*time.Second), now.Add(2*time.Second)
	first.ExpiresAt, second.ExpiresAt = first.IssuedAt.Add(90*24*time.Hour), second.IssuedAt.Add(90*24*time.Hour)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, replacement := range []ClientDeviceCredential{first, second} {
		replacement := replacement
		go func() {
			<-start
			results <- store.RenewClientDeviceCredentialWithAudit(ctx, current.ID, now.Add(2*time.Second), replacement, "192.0.2.60")
		}()
	}
	close(start)
	var succeeded, rejected int
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if errors.Is(err, sql.ErrNoRows) {
			rejected++
		} else {
			t.Fatalf("unexpected concurrent renewal error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent renewal winners changed: succeeded=%d rejected=%d", succeeded, rejected)
	}
	credentials, err := store.ClientDeviceCredentials(ctx, clientID)
	if err != nil || len(credentials) != 2 || credentials[0].Status != "superseded" || credentials[1].Status != "active" {
		t.Fatalf("concurrent renewal state changed: %+v %v", credentials, err)
	}
	active, err := store.ActiveClientDeviceCredential(ctx, clientID, now.Add(2*time.Second))
	if err != nil || active.ID != credentials[1].ID {
		t.Fatalf("active credential lookup changed: %+v %v", active, err)
	}
}

func testClientDeviceAuthenticationContract(t *testing.T, store clientDeviceAuthenticationStore) {
	t.Helper()
	ctx := t.Context()
	const clientID = "device-auth-contract"
	client, err := store.CreateClient(ctx, clientID, "synthetic-status-token")
	if err != nil || client.AuthMode != ClientAuthTokenOnly {
		t.Fatalf("safe client authentication default changed: %+v %v", client, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tokenHash := strings.Repeat("a", 64)
	token := ClientEnrollmentToken{ID: "enrollment-contract-01", ClientID: clientID, TokenHash: tokenHash, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	if err := store.CreateClientEnrollmentTokenWithAudit(ctx, token, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	credential := ClientDeviceCredential{ID: "credential-contract-01", ClientID: clientID, FingerprintSHA256: strings.Repeat("b", 64), Serial: "1ab", URISAN: "urn:stumpfworks:identity:client:" + clientID, PublicKeyAlgorithm: "ECDSA-P256", IssuerID: "stumpfworks-device-ca-01", IssuedAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour)}
	if err := store.EnrollClientDeviceCredentialWithAudit(ctx, tokenHash, now.Add(time.Second), credential, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if err := store.EnrollClientDeviceCredentialWithAudit(ctx, tokenHash, now.Add(2*time.Second), credential, "192.0.2.10"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("enrollment replay accepted: %v", err)
	}
	credentials, err := store.ClientDeviceCredentials(ctx, clientID)
	if err != nil || len(credentials) != 1 || credentials[0].FingerprintSHA256 != credential.FingerprintSHA256 || credentials[0].Status != "active" {
		t.Fatalf("credential metadata changed: %+v %v", credentials, err)
	}
	if err := store.SetClientAuthenticationModeWithAudit(ctx, clientID, ClientAuthCertificatePreferred, "192.0.2.10", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err = store.ClientByID(ctx, clientID)
	if err != nil || client.AuthMode != ClientAuthCertificatePreferred {
		t.Fatalf("authentication mode not persisted: %+v %v", client, err)
	}
	replacement := credential
	replacement.ID = "credential-contract-02"
	replacement.FingerprintSHA256 = strings.Repeat("d", 64)
	replacement.Serial = "2ab"
	replacement.IssuedAt = now.Add(4 * time.Second)
	replacement.ExpiresAt = replacement.IssuedAt.Add(90 * 24 * time.Hour)
	if err := store.RenewClientDeviceCredentialWithAudit(ctx, credential.ID, now.Add(4*time.Second), replacement, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if err := store.RenewClientDeviceCredentialWithAudit(ctx, credential.ID, now.Add(5*time.Second), replacement, "192.0.2.10"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("renewal replay accepted: %v", err)
	}
	credentials, err = store.ClientDeviceCredentials(ctx, clientID)
	if err != nil || len(credentials) != 2 || credentials[0].Status != "superseded" || credentials[1].Status != "active" {
		t.Fatalf("renewal state changed: %+v %v", credentials, err)
	}
	if err := store.RevokeClientDeviceCredentialWithAudit(ctx, clientID, replacement.ID, "192.0.2.10", now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetClientAuthenticationModeWithAudit(ctx, clientID, ClientAuthCertificateRequired, "192.0.2.10", now.Add(7*time.Second)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("required mode accepted without active credential: %v", err)
	}
	if err := store.SetClientAuthenticationModeWithAudit(ctx, clientID, ClientAuthTokenOnly, "192.0.2.10", now.Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteClientEnrollmentAuditFailureRollsBackToken(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateClient(t.Context(), "audit-rollback-client", "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`CREATE TRIGGER reject_client_enrollment_audit BEFORE INSERT ON audit_log WHEN NEW.event_type='client_enrollment_created' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token := ClientEnrollmentToken{ID: "audit-rollback-enrollment", ClientID: "audit-rollback-client", TokenHash: strings.Repeat("c", 64), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateClientEnrollmentTokenWithAudit(t.Context(), token, "192.0.2.20"); err == nil {
		t.Fatal("synthetic audit failure accepted")
	}
	var count int
	if err := store.DB.QueryRow(`SELECT count(*) FROM client_enrollment_tokens`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("audit failure left enrollment token: count=%d err=%v", count, err)
	}
}

func TestSQLiteClientDeviceCredentialRejectsMismatchedURISAN(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateClient(t.Context(), "uri-bound-client", "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tokenHash := strings.Repeat("e", 64)
	token := ClientEnrollmentToken{ID: "uri-bound-enrollment", ClientID: "uri-bound-client", TokenHash: tokenHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateClientEnrollmentTokenWithAudit(t.Context(), token, "192.0.2.30"); err != nil {
		t.Fatal(err)
	}
	credential := ClientDeviceCredential{ID: "uri-bound-credential", ClientID: "uri-bound-client", FingerprintSHA256: strings.Repeat("f", 64), Serial: "3ab", URISAN: "urn:stumpfworks:identity:client:another-client", PublicKeyAlgorithm: "ECDSA-P256", IssuerID: "stumpfworks-device-ca-01", IssuedAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour)}
	if err := store.EnrollClientDeviceCredentialWithAudit(t.Context(), tokenHash, now.Add(time.Second), credential, "192.0.2.30"); !errors.Is(err, ErrInvalidClientDeviceCredential) {
		t.Fatalf("mismatched URI SAN accepted: %v", err)
	}
	var consumed int
	if err := store.DB.QueryRow(`SELECT count(*) FROM client_enrollment_tokens WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil || consumed != 0 {
		t.Fatalf("invalid credential consumed enrollment token: count=%d err=%v", consumed, err)
	}
}

func TestSQLiteClientDeviceRenewalAuditFailureRollsBackReplacement(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := t.Context()
	const clientID = "renewal-rollback-client"
	if _, err := store.CreateClient(ctx, clientID, "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tokenHash := strings.Repeat("1", 64)
	token := ClientEnrollmentToken{ID: "renewal-rollback-enrollment", ClientID: clientID, TokenHash: tokenHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateClientEnrollmentTokenWithAudit(ctx, token, "192.0.2.40"); err != nil {
		t.Fatal(err)
	}
	current := ClientDeviceCredential{ID: "renewal-current", ClientID: clientID, FingerprintSHA256: strings.Repeat("2", 64), Serial: "4ab", URISAN: "urn:stumpfworks:identity:client:" + clientID, PublicKeyAlgorithm: "ECDSA-P256", IssuerID: "stumpfworks-device-ca-01", IssuedAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour)}
	if err := store.EnrollClientDeviceCredentialWithAudit(ctx, tokenHash, now.Add(time.Second), current, "192.0.2.40"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`CREATE TRIGGER reject_client_renewal_audit BEFORE INSERT ON audit_log WHEN NEW.event_type='client_device_renewed' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	replacement := current
	replacement.ID = "renewal-replacement"
	replacement.FingerprintSHA256 = strings.Repeat("3", 64)
	replacement.Serial = "5ab"
	replacement.IssuedAt = now.Add(2 * time.Second)
	replacement.ExpiresAt = replacement.IssuedAt.Add(90 * 24 * time.Hour)
	if err := store.RenewClientDeviceCredentialWithAudit(ctx, current.ID, now.Add(2*time.Second), replacement, "192.0.2.40"); err == nil {
		t.Fatal("synthetic renewal audit failure accepted")
	}
	credentials, err := store.ClientDeviceCredentials(ctx, clientID)
	if err != nil || len(credentials) != 1 || credentials[0].ID != current.ID || credentials[0].Status != "active" {
		t.Fatalf("audit failure changed credentials: %+v %v", credentials, err)
	}
}

func TestSQLiteClientDeviceMutationAuditFailuresRollBack(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := t.Context()
	const clientID = "mutation-rollback-client"
	if _, err := store.CreateClient(ctx, clientID, "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tokenHash := strings.Repeat("6", 64)
	token := ClientEnrollmentToken{ID: "mutation-rollback-enrollment", ClientID: clientID, TokenHash: tokenHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateClientEnrollmentTokenWithAudit(ctx, token, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	credential := ClientDeviceCredential{ID: "mutation-rollback-credential", ClientID: clientID, FingerprintSHA256: strings.Repeat("7", 64), Serial: "6ab", URISAN: "urn:stumpfworks:identity:client:" + clientID, PublicKeyAlgorithm: "ECDSA-P256", IssuerID: "stumpfworks-device-ca-01", IssuedAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour)}
	createRejectTrigger := func(eventType string) {
		t.Helper()
		if _, err := store.DB.Exec(`CREATE TRIGGER reject_device_mutation_audit BEFORE INSERT ON audit_log WHEN NEW.event_type='` + eventType + `' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END`); err != nil {
			t.Fatal(err)
		}
	}
	dropRejectTrigger := func() {
		t.Helper()
		if _, err := store.DB.Exec(`DROP TRIGGER reject_device_mutation_audit`); err != nil {
			t.Fatal(err)
		}
	}

	createRejectTrigger("client_device_enrolled")
	if err := store.EnrollClientDeviceCredentialWithAudit(ctx, tokenHash, now.Add(time.Second), credential, "192.0.2.50"); err == nil {
		t.Fatal("synthetic enrollment audit failure accepted")
	}
	var consumed, credentialCount int
	if err := store.DB.QueryRow(`SELECT count(*) FROM client_enrollment_tokens WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if err := store.DB.QueryRow(`SELECT count(*) FROM client_device_credentials`).Scan(&credentialCount); err != nil || consumed != 0 || credentialCount != 0 {
		t.Fatalf("enrollment audit failure changed state: consumed=%d credentials=%d err=%v", consumed, credentialCount, err)
	}
	dropRejectTrigger()
	if err := store.EnrollClientDeviceCredentialWithAudit(ctx, tokenHash, now.Add(2*time.Second), credential, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}

	createRejectTrigger("client_authentication_mode_changed")
	if err := store.SetClientAuthenticationModeWithAudit(ctx, clientID, ClientAuthCertificatePreferred, "192.0.2.50", now.Add(3*time.Second)); err == nil {
		t.Fatal("synthetic mode audit failure accepted")
	}
	client, err := store.ClientByID(ctx, clientID)
	if err != nil || client.AuthMode != ClientAuthTokenOnly {
		t.Fatalf("mode audit failure changed client: %+v %v", client, err)
	}
	dropRejectTrigger()

	createRejectTrigger("client_device_revoked")
	if err := store.RevokeClientDeviceCredentialWithAudit(ctx, clientID, credential.ID, "192.0.2.50", now.Add(4*time.Second)); err == nil {
		t.Fatal("synthetic revocation audit failure accepted")
	}
	credentials, err := store.ClientDeviceCredentials(ctx, clientID)
	if err != nil || len(credentials) != 1 || credentials[0].Status != "active" || credentials[0].RevokedAt.Valid {
		t.Fatalf("revocation audit failure changed credential: %+v %v", credentials, err)
	}
}

func TestSQLiteClientTokenFallbackAuditFailureRollsBackStatus(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := t.Context()
	const clientID = "fallback-audit-rollback-client"
	if _, err := store.CreateClient(ctx, clientID, "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`CREATE TRIGGER reject_client_fallback_audit BEFORE INSERT ON audit_log WHEN NEW.event_type='client_certificate_token_fallback' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateClientStatusWithUpdateAndTokenFallbackAudit(ctx, clientID, "9.9.9", "ok", "ok", "ok", "ok", nil, "192.0.2.80"); err == nil {
		t.Fatal("synthetic fallback audit failure accepted")
	}
	client, err := store.ClientByID(ctx, clientID)
	if err != nil || client.Version != "" || client.LastSeenAt != nil {
		t.Fatalf("fallback audit failure changed status: %+v %v", client, err)
	}
}
