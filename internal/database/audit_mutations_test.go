package database

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

type atomicBadgeStore interface {
	CreateUser(context.Context, string, string, string) (User, error)
	CreateBadge(context.Context, int64, string, string) (Badge, error)
	ReplaceBadgePending(context.Context, int64, string, string) (Badge, error)
	GetBadge(context.Context, int64) (Badge, error)
	Audits(context.Context) ([]Audit, error)
	WriteAudit(context.Context, Audit) error
	RevokeActiveBadgeForUserWithAudit(context.Context, int64, int64, string) (UserBadge, error)
	ActivatePendingBadgeForUserWithAudit(context.Context, int64, int64, string) error
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
