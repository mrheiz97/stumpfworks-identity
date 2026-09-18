package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

type badgeStore interface {
	CreateUser(context.Context, string, string, string) (User, error)
	CreateBadge(context.Context, int64, string, string) (Badge, error)
	GetBadge(context.Context, int64) (Badge, error)
	BadgeByCode(context.Context, string) (Badge, error)
	Badges(context.Context) ([]Badge, error)
	ActiveBadgesByUser(context.Context, int64) ([]UserBadge, error)
	ReplaceBadgePending(context.Context, int64, string, string) (Badge, error)
	ActivatePendingBadgeForUser(context.Context, int64, int64) error
	RevokeActiveBadgeForUser(context.Context, int64, int64) (UserBadge, error)
	Revoke(context.Context, int64) error
	Used(context.Context, int64) error
}

func TestSQLiteBadgeContract(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testBadgeContract(t, s)
}

func testBadgeContract(t *testing.T, s badgeStore) {
	t.Helper()
	ctx := t.Context()
	owner, err := s.CreateUser(ctx, "badge-owner", "Synthetic owner", "")
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := s.CreateUser(ctx, "badge-stranger", "Synthetic stranger", "")
	if err != nil {
		t.Fatal(err)
	}
	badge, err := s.CreateBadge(ctx, owner.ID, "synthetic-badge-contract-hash", "contract badge")
	if err != nil || !badge.Enabled || badge.ActivationPending {
		t.Fatal("badge creation failed")
	}
	if found, err := s.BadgeByCode(ctx, badge.BadgeCode); err != nil || found.ID != badge.ID || found.TokenHash != "synthetic-badge-contract-hash" {
		t.Fatal("badge lookup failed")
	}
	if badges, err := s.Badges(ctx); err != nil || len(badges) == 0 {
		t.Fatal("badge listing failed")
	}
	if active, err := s.ActiveBadgesByUser(ctx, stranger.ID); err != nil || len(active) != 0 {
		t.Fatal("active badge ownership leaked")
	}
	if _, err := s.RevokeActiveBadgeForUser(ctx, badge.ID, stranger.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("foreign badge revocation accepted")
	}
	if err := s.Used(ctx, badge.ID); err != nil {
		t.Fatal(err)
	}
	if found, err := s.GetBadge(ctx, badge.ID); err != nil || !found.LastUsedAt.Valid {
		t.Fatal("badge usage not recorded")
	}
	replacement, err := s.ReplaceBadgePending(ctx, badge.ID, "synthetic-replacement-hash", "replacement")
	if err != nil || replacement.Enabled || !replacement.ActivationPending || replacement.UserID != owner.ID {
		t.Fatal("pending replacement failed")
	}
	if old, err := s.GetBadge(ctx, badge.ID); err != nil || old.Enabled || !old.RevokedAt.Valid {
		t.Fatal("replacement did not revoke original")
	}
	if _, err := s.ReplaceBadgePending(ctx, badge.ID, "unused", "duplicate replacement"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("revoked badge replaced twice")
	}
	if err := s.ActivatePendingBadgeForUser(ctx, replacement.ID, stranger.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("foreign pending activation accepted")
	}
	if err := s.ActivatePendingBadgeForUser(ctx, replacement.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivatePendingBadgeForUser(ctx, replacement.ID, owner.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("repeated activation accepted")
	}
	if active, err := s.ActiveBadgesByUser(ctx, owner.ID); err != nil || len(active) != 1 || active[0].ID != replacement.ID {
		t.Fatal("active replacement list failed")
	}
	if _, err := s.RevokeActiveBadgeForUser(ctx, replacement.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeActiveBadgeForUser(ctx, replacement.ID, owner.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("repeated revocation accepted")
	}
	if active, err := s.ActiveBadgesByUser(ctx, owner.ID); err != nil || len(active) != 0 {
		t.Fatal("revoked badge still active")
	}
	other, err := s.CreateBadge(ctx, stranger.ID, "synthetic-stranger-hash", "other")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.ReplaceBadgePending(ctx, other.ID, "synthetic-cancelled-hash", "cancelled")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, pending.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivatePendingBadgeForUser(ctx, pending.ID, stranger.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("cancelled pending badge activated")
	}
}
