// Package certificatecontract supplies portable certificate conformance tests.
// It is test support, not a runtime certificate implementation. Future framework
// candidates can be tested by changing only the adapter passed to RunPeer.
package certificatecontract

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

type Peer struct{ URI, FingerprintSHA256, Serial string }
type PeerValidator func(*tls.ConnectionState, time.Time) (Peer, error)

// RunPeer characterizes the Identity adapter's current certificate contract.
// Synthetic VerifiedChains are deliberate: this suite tests consumption of the
// TLS verification result, not CA trust. Real handshake tests remain separate.
// Namespace/identifier cases are consumer policy and stay in deviceauth tests.
func RunPeer(t *testing.T, validate PeerValidator, uri string) {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	issue := func(mutate func(*x509.Certificate)) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
		if mutate != nil {
			mutate(c)
		}
		der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	valid := issue(nil)
	verified := func(c *x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}, VerifiedChains: [][]*x509.Certificate{{c}}}
	}
	t.Run("projection", func(t *testing.T) {
		got, err := validate(verified(valid), now)
		sum := sha256.Sum256(valid.Raw)
		if err != nil || got.URI != uri || got.Serial != "2a" || got.FingerprintSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("verified leaf projection changed", err)
		}
	})
	t.Run("mixed explicit EKUs retain client usage", func(t *testing.T) {
		c := issue(func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		})
		if _, err := validate(verified(c), now); err != nil {
			t.Fatal("existing mixed-EKU compatibility changed")
		}
	})
	// Go x509 validity includes NotAfter; Identity's active-credential database
	// check separately requires expires_at > now. Preserve both contracts.
	for _, at := range []time.Time{valid.NotBefore, valid.NotAfter} {
		t.Run("inclusive_x509_"+at.Format(time.RFC3339), func(t *testing.T) {
			if _, err := validate(verified(valid), at); err != nil {
				t.Fatal("X509 validity boundary changed", err)
			}
		})
	}
	tests := []struct {
		name  string
		state *tls.ConnectionState
		at    time.Time
	}{
		{"missing state", nil, now}, {"missing leaf", &tls.ConnectionState{}, now},
		{"unverified leaf", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{valid}}, now},
		{"empty verified chain", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{valid}, VerifiedChains: [][]*x509.Certificate{{}}}, now},
		{"different verified leaf", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{valid}, VerifiedChains: [][]*x509.Certificate{{issue(nil)}}}, now},
		{"nil peer leaf", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{nil}, VerifiedChains: [][]*x509.Certificate{{valid}}}, now},
		{"nil verified leaf", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{valid}, VerifiedChains: [][]*x509.Certificate{{nil}}}, now},
		{"zero time", verified(valid), time.Time{}},
		{"before validity", verified(valid), valid.NotBefore.Add(-time.Nanosecond)},
		{"after validity", verified(valid), valid.NotAfter.Add(time.Nanosecond)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validate(tc.state, tc.at)
			if err == nil || got != (Peer{}) {
				t.Fatal("invalid TLS evidence accepted or partial identity returned")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{"server EKU", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{"missing explicit EKU", func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{"any EKU only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }},
		{"missing URI", func(c *x509.Certificate) { c.URIs = nil }},
		{"CN cannot replace URI", func(c *x509.Certificate) { c.URIs = nil; c.Subject.CommonName = "contract-device" }},
		{"duplicate URI", func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) }},
		{"extra DNS SAN", func(c *x509.Certificate) { c.DNSNames = []string{"device.example.test"} }},
		{"extra IP SAN", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} }},
		{"extra mail SAN", func(c *x509.Certificate) { c.EmailAddresses = []string{"device@example.test"} }},
		{"zero serial", func(c *x509.Certificate) { c.SerialNumber = big.NewInt(0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := validate(verified(issue(tc.mutate)), now); err == nil || got != (Peer{}) {
				t.Fatal("invalid certificate accepted")
			}
		})
	}
	t.Run("nil URI value", func(t *testing.T) {
		c := *valid
		c.URIs = []*url.URL{nil}
		if got, err := validate(verified(&c), now); err == nil || got != (Peer{}) {
			t.Fatal("nil URI accepted")
		}
	})
}
