package deviceauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestFromTLSAcceptsExactVerifiedDeviceIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	certificate := syntheticClientCertificate(t, now, []string{"urn:stumpfworks:identity:client:wyse01-greeter"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	identity, err := FromTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}, now)
	if err != nil || identity.ClientID != "wyse01-greeter" || len(identity.FingerprintSHA256) != 64 || identity.Serial != "2a" || identity.URISAN != certificate.URIs[0].String() {
		t.Fatalf("verified identity changed: %+v %v", identity, err)
	}
}

func TestFromTLSRejectsInvalidCertificateIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name     string
		uris     []string
		usages   []x509.ExtKeyUsage
		dnsNames []string
		ips      []net.IP
		at       time.Time
		verified bool
	}{
		{name: "unverified", uris: []string{"urn:stumpfworks:identity:client:wyse01-greeter"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, at: now},
		{name: "missing URI", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, at: now, verified: true},
		{name: "duplicate URI", uris: []string{"urn:stumpfworks:identity:client:wyse01-greeter", "urn:stumpfworks:identity:client:other"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, at: now, verified: true},
		{name: "wrong namespace", uris: []string{"urn:example:client:wyse01-greeter"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, at: now, verified: true},
		{name: "invalid client ID", uris: []string{"urn:stumpfworks:identity:client:wyse 01"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, at: now, verified: true},
		{name: "server EKU", uris: []string{"urn:stumpfworks:identity:client:wyse01-greeter"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, at: now, verified: true},
		{name: "extra DNS identity", uris: []string{"urn:stumpfworks:identity:client:wyse01-greeter"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, dnsNames: []string{"wyse01.example.test"}, at: now, verified: true},
		{name: "extra IP identity", uris: []string{"urn:stumpfworks:identity:client:wyse01-greeter"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ips: []net.IP{net.ParseIP("192.0.2.1")}, at: now, verified: true},
		{name: "not yet valid", uris: []string{"urn:stumpfworks:identity:client:wyse01-greeter"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, at: now.Add(-2 * time.Hour), verified: true},
		{name: "expired", uris: []string{"urn:stumpfworks:identity:client:wyse01-greeter"}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, at: now.Add(2 * time.Hour), verified: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate := syntheticClientCertificate(t, now, test.uris, test.usages, test.dnsNames, test.ips)
			state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			if test.verified {
				state.VerifiedChains = [][]*x509.Certificate{{certificate}}
			}
			if _, err := FromTLS(state, test.at); err == nil {
				t.Fatal("invalid certificate identity accepted")
			}
		})
	}
}

func syntheticClientCertificate(t *testing.T, now time.Time, uriValues []string, usages []x509.ExtKeyUsage, dnsNames []string, ips []net.IP) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uris []*url.URL
	for _, value := range uriValues {
		parsed, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, parsed)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "ignored-client-common-name"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, URIs: uris, DNSNames: dnsNames, IPAddresses: ips}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
