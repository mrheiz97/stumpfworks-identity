package certificatecontract

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// IssuedInput represents caller-owned material. Never format this object in
// diagnostics: it includes a private key only to adapt Identity's current API.
// A future framework verifier should accept the expected PUBLIC key instead.
type IssuedInput struct {
	CertificatePEM, CAPEM, PinnedCAPEM []byte
	Key                                *ecdsa.PrivateKey
	ExpiresAt                          time.Time
}
type IssuedValidator func(IssuedInput, time.Time) error

func RunIssued(t *testing.T, validate IssuedValidator, identityURI string) {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	newKey := func() *ecdsa.PrivateKey {
		t.Helper()
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return key
	}
	key, caKey := newKey(), newKey()
	u, e := url.Parse(identityURI)
	if e != nil {
		t.Fatal(e)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	rootDER, e := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	issue := func(mutate func(*x509.Certificate), signer *ecdsa.PrivateKey) IssuedInput {
		t.Helper()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
		if mutate != nil {
			mutate(leaf)
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		return IssuedInput{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), CAPEM: caPEM, PinnedCAPEM: caPEM, Key: key, ExpiresAt: leaf.NotAfter}
	}
	valid := issue(nil, caKey)
	otherCAKey := newKey()
	otherDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &otherCAKey.PublicKey, otherCAKey)
	if err != nil {
		t.Fatal(err)
	}
	otherCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER})
	expiredTemplate := *rootTemplate
	expiredTemplate.NotAfter = now.Add(-time.Second)
	expiredDER, err := x509.CreateCertificate(rand.Reader, &expiredTemplate, &expiredTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER})
	t.Run("verified pinned material", func(t *testing.T) {
		if err := validate(valid, now); err != nil {
			t.Fatal("valid issued material rejected")
		}
	})
	for _, at := range []time.Time{now.Add(-time.Hour), now.Add(time.Hour)} {
		t.Run("inclusive_x509_"+at.Format(time.RFC3339), func(t *testing.T) {
			if validate(valid, at) != nil {
				t.Fatal("X509 validity boundary changed")
			}
		})
	}
	t.Run("mixed explicit EKUs retain client usage", func(t *testing.T) {
		v := issue(func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}, caKey)
		if validate(v, now) != nil {
			t.Fatal("mixed EKU contract changed")
		}
	})
	t.Run("bootstrap without prior device CA pin", func(t *testing.T) {
		v := valid
		v.PinnedCAPEM = nil
		if err := validate(v, now); err != nil {
			t.Fatal("bootstrap contract changed")
		}
	})
	for _, tc := range []struct {
		name  string
		input IssuedInput
		at    time.Time
	}{
		{"before certificate validity", valid, now.Add(-2 * time.Hour)},
		{"expired certificate", valid, now.Add(2 * time.Hour)},
		{"zero validation clock", valid, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validate(tc.input, tc.at) == nil {
				t.Fatal("invalid issued material accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*IssuedInput)
	}{
		{"wrong public key", func(v *IssuedInput) { v.Key = newKey() }},
		{"missing expected key", func(v *IssuedInput) { v.Key = nil }},
		{"wrong CA pin", func(v *IssuedInput) { v.PinnedCAPEM = v.CertificatePEM }},
		{"chain not issued by supplied root", func(v *IssuedInput) { v.CAPEM = otherCA; v.PinnedCAPEM = nil }},
		{"expired root", func(v *IssuedInput) { v.CAPEM = expiredCA; v.PinnedCAPEM = nil }},
		{"CA is leaf", func(v *IssuedInput) { v.CAPEM = v.CertificatePEM }},
		{"malformed certificate", func(v *IssuedInput) { v.CertificatePEM = []byte("invalid") }},
		{"malformed CA", func(v *IssuedInput) { v.CAPEM = []byte("invalid") }},
		{"extra certificate", func(v *IssuedInput) {
			v.CertificatePEM = append(append([]byte{}, v.CertificatePEM...), v.CertificatePEM...)
		}},
		{"extra CA", func(v *IssuedInput) { v.CAPEM = append(append([]byte{}, v.CAPEM...), v.CAPEM...) }},
		{"wrong expiry metadata", func(v *IssuedInput) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := valid
			tc.mutate(&v)
			if validate(v, now) == nil {
				t.Fatal("invalid material accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{"server EKU", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{"missing EKU", func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{"unexpected URI", func(c *x509.Certificate) { c.URIs = []*url.URL{{Scheme: "urn", Opaque: "example:other-device"}} }},
		{"extra DNS identity", func(c *x509.Certificate) { c.DNSNames = []string{"device.example.test"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validate(issue(tc.mutate, caKey), now) == nil {
				t.Fatal("invalid leaf accepted")
			}
		})
	}
	t.Run("pin compares certificate DER not PEM layout", func(t *testing.T) {
		v := valid
		v.PinnedCAPEM = append([]byte("\n"), append(v.PinnedCAPEM, '\n')...)
		if validate(v, now) != nil {
			t.Fatal("same pinned CA rejected")
		}
	})
}
