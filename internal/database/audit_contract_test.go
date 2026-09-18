package database

import (
	"context"
	"testing"
)

type auditReader interface {
	Audits(context.Context) ([]Audit, error)
	RecentBadgeAuthByUser(context.Context, string) ([]UserAuthEvent, error)
}

func TestSQLiteAuditReadContract(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testAuditReadContract(t, s, func(event Audit) error {
		s.Audit(t.Context(), event.EventType, event.BadgeID, event.Username, event.ClientID, event.Success, event.IPAddress, event.Details)
		return nil
	})
}

func testAuditReadContract(t *testing.T, s auditReader, write func(Audit) error) {
	t.Helper()
	for i := 0; i < 25; i++ {
		if err := write(Audit{EventType: "auth_success", BadgeID: "contract-audit-badge", Username: "Audit-Owner", ClientID: "contract-audit-client", Success: true, Details: "synthetic audit"}); err != nil {
			t.Fatal("audit fixture write failed")
		}
	}
	for _, event := range []Audit{
		{EventType: "auth_failed", BadgeID: "foreign-badge", Username: "other-user", ClientID: "other-client"},
		{EventType: "badge_created", BadgeID: "unrelated-badge", Username: "Audit-Owner", Success: true},
	} {
		if err := write(event); err != nil {
			t.Fatal("audit fixture write failed")
		}
	}
	events, err := s.RecentBadgeAuthByUser(t.Context(), "AUDIT-OWNER")
	if err != nil || len(events) != 20 {
		t.Fatal("audit history limit changed")
	}
	for _, event := range events {
		if event.BadgeID != "contract-audit-badge" || event.ClientID != "contract-audit-client" || !event.Success || event.Timestamp.IsZero() {
			t.Fatal("unrelated audit event leaked")
		}
	}
	all, err := s.Audits(t.Context())
	if err != nil || len(all) < 27 || len(all) > 200 {
		t.Fatal("audit listing failed")
	}
}
