package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func emergencyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func testEmergencyAdminContract(t *testing.T, store ApplicationStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	grant := EmergencyAdminGrant{ID: "emergency-contract-grant", TokenHash: emergencyHash("one-time-emergency-token"), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	if err := store.CreateEmergencyAdminGrantWithAudit(ctx, grant, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int64
	var winning EmergencyAdminGrant
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			consumed, err := store.ConsumeEmergencyAdminGrantWithAudit(ctx, grant.TokenHash, emergencyHash(string(rune('a'+i))), now.Add(time.Second), "192.0.2.2")
			if err == nil {
				winners.Add(1)
				mu.Lock()
				winning = consumed
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("parallel replay winners=%d", winners.Load())
	}
	if _, err := store.ActiveEmergencyAdminSession(ctx, winning.SessionHash, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeEmergencyAdminGrantWithAudit(ctx, winning.ID, "192.0.2.3"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActiveEmergencyAdminSession(ctx, winning.SessionHash, now.Add(3*time.Second)); err == nil {
		t.Fatal("revoked emergency session remained active")
	}
	audits, err := store.Audits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, event := range audits {
		counts[event.EventType]++
	}
	for _, event := range []string{"emergency_admin_grant_created", "emergency_admin_login", "emergency_admin_grant_revoked"} {
		if counts[event] != 1 {
			t.Fatalf("audit %s count=%d", event, counts[event])
		}
	}
}

func TestSQLiteEmergencyAdminContract(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	testEmergencyAdminContract(t, store)
}

func TestSQLiteEmergencyAdminAuditFailureRollsBack(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.DB.Exec(`CREATE TRIGGER reject_emergency_audit BEFORE INSERT ON audit_log WHEN NEW.event_type LIKE 'emergency_admin_%' BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant := EmergencyAdminGrant{ID: "rollback-grant", TokenHash: emergencyHash("rollback-token"), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	if err = store.CreateEmergencyAdminGrantWithAudit(t.Context(), grant, ""); err == nil {
		t.Fatal("audit failure accepted grant")
	}
	var count int
	if err = store.DB.QueryRow(`SELECT count(*) FROM emergency_admin_grants`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("grant escaped audit rollback: %d %v", count, err)
	}
}

func TestSQLiteEmergencyAdminLoginAuditFailureLeavesTokenUnused(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	grant := EmergencyAdminGrant{ID: "login-rollback-grant", TokenHash: emergencyHash("login-rollback-token"), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	if err = store.CreateEmergencyAdminGrantWithAudit(t.Context(), grant, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec(`CREATE TRIGGER reject_emergency_login_audit BEFORE INSERT ON audit_log WHEN NEW.event_type='emergency_admin_login' BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ConsumeEmergencyAdminGrantWithAudit(t.Context(), grant.TokenHash, emergencyHash("first-session"), now.Add(time.Second), ""); err == nil {
		t.Fatal("login escaped audit failure")
	}
	if _, err = store.DB.Exec(`DROP TRIGGER reject_emergency_login_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ConsumeEmergencyAdminGrantWithAudit(t.Context(), grant.TokenHash, emergencyHash("second-session"), now.Add(2*time.Second), ""); err != nil {
		t.Fatal("audit rollback consumed token")
	}
}

func TestSQLiteEmergencyAdminRevokeAuditFailureLeavesSessionActive(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	grant := EmergencyAdminGrant{ID: "revoke-rollback-grant", TokenHash: emergencyHash("revoke-rollback-token"), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	if err = store.CreateEmergencyAdminGrantWithAudit(t.Context(), grant, ""); err != nil {
		t.Fatal(err)
	}
	sessionHash := emergencyHash("revoke-rollback-session")
	if _, err = store.ConsumeEmergencyAdminGrantWithAudit(t.Context(), grant.TokenHash, sessionHash, now.Add(time.Second), ""); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec(`CREATE TRIGGER reject_emergency_revoke_audit BEFORE INSERT ON audit_log WHEN NEW.event_type='emergency_admin_grant_revoked' BEGIN SELECT RAISE(ABORT,'synthetic audit rejection'); END`); err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeEmergencyAdminSessionWithAudit(t.Context(), sessionHash, ""); err == nil {
		t.Fatal("revocation escaped audit failure")
	}
	if _, err = store.ActiveEmergencyAdminSession(t.Context(), sessionHash, now.Add(2*time.Second)); err != nil {
		t.Fatal("audit rollback revoked emergency session")
	}
}
