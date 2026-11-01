package database

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func testClientCertificateSummaryContract(t *testing.T, s ApplicationStore, exec func(string, ...any) error) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	counter := 0
	add := func(client, status string, issued, expires, created time.Time) {
		counter++
		id := fmt.Sprintf("summary-credential-%d", counter)
		digest := sha256.Sum256([]byte(id))
		if err := exec(`INSERT INTO client_device_credentials(id,client_id,fingerprint_sha256,serial,uri_san,public_key_algorithm,issuer_id,issued_at,expires_at,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'ECDSA-P256','synthetic-ca',$6,$7,$8,$9,$9)`, id, client, hex.EncodeToString(digest[:]), fmt.Sprintf("%x", counter+100), "urn:stumpfworks:identity:client:"+client, issued, expires, status, created); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"none", "active", "expired", "pending", "revoked", "superseded"} {
		if _, err := s.CreateClient(t.Context(), "summary-"+name, "synthetic-token-hash"); err != nil {
			t.Fatal(err)
		}
	}
	add("summary-active", "active", now.Add(-time.Hour), now.Add(60*24*time.Hour), now.Add(-time.Hour))
	add("summary-active", "pending", now.Add(-time.Minute), now.Add(90*24*time.Hour), now.Add(-time.Minute))
	add("summary-active", "revoked", now.Add(-24*time.Hour), now.Add(90*24*time.Hour), now)
	add("summary-expired", "active", now.Add(-90*24*time.Hour), now.Add(-time.Second), now.Add(-90*24*time.Hour))
	add("summary-pending", "pending", now.Add(-time.Hour), now.Add(time.Hour), now.Add(-ClientDeviceActivationWindow))
	add("summary-revoked", "revoked", now.Add(-time.Hour), now.Add(time.Hour), now)
	add("summary-superseded", "superseded", now.Add(-time.Hour), now.Add(time.Hour), now)
	rows, err := s.ClientCertificateSummaries(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]ClientCertificateSummary{}
	for _, v := range rows {
		found[v.ClientID] = v
	}
	for client, status := range map[string]string{"none": "", "active": "active", "expired": "active", "pending": "pending", "revoked": "revoked", "superseded": "superseded"} {
		v, ok := found["summary-"+client]
		if !ok || v.Status != status {
			t.Fatalf("%s: %+v", client, v)
		}
		if client != "none" && (!v.ExpiresAt.Valid || !v.IssuedAt.Valid || !v.CreatedAt.Valid) {
			t.Fatal("timestamp projection lost", v)
		}
	}
	if !found["summary-active"].PendingActivation || found["summary-pending"].PendingActivation {
		t.Fatal("activation deadline boundary wrong")
	}
	if !found["summary-active"].ExpiresAt.Time.Equal(now.Add(60 * 24 * time.Hour)) {
		t.Fatal("pending renewal hid current expiry")
	}
}
func TestSQLiteClientCertificateSummaries(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testClientCertificateSummaryContract(t, s, func(q string, a ...any) error { _, e := s.DB.Exec(q, a...); return e })
}
