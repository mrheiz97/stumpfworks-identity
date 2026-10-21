package passkey

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestAdapterRequiresExactHTTPSBoundary(t *testing.T) {
	valid, err := New("login01.ad.stumpfworks.de", "https://login01.ad.stumpfworks.de:8080")
	if err != nil || valid.RPID() != "login01.ad.stumpfworks.de" || valid.Origin() != "https://login01.ad.stumpfworks.de:8080" {
		t.Fatalf("valid Passkey boundary rejected: %v", err)
	}
	for _, test := range []struct{ rpID, origin string }{
		{"login01.ad.stumpfworks.de", "http://login01.ad.stumpfworks.de:8080"},
		{"login01.ad.stumpfworks.de", "https://other.ad.stumpfworks.de:8080"},
		{"login01.ad.stumpfworks.de:8080", "https://login01.ad.stumpfworks.de:8080"},
		{"login01.ad.stumpfworks.de", "https://login01.ad.stumpfworks.de:8080/path"},
	} {
		if _, err := New(test.rpID, test.origin); err == nil {
			t.Fatalf("unsafe Passkey boundary accepted: %+v", test)
		}
	}
}

func TestDiscoverableLoginSessionIsBoundedAndStrict(t *testing.T) {
	adapter, err := New("login01.ad.stumpfworks.de", "https://login01.ad.stumpfworks.de:8080")
	if err != nil {
		t.Fatal(err)
	}
	options, encoded, err := adapter.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	if options == nil || options.Response.RelyingPartyID != adapter.RPID() || options.Response.UserVerification != protocol.VerificationRequired {
		t.Fatal("discoverable login options weakened RP or user-verification policy")
	}
	session, err := DecodeSession(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if session.RelyingPartyID != adapter.RPID() || session.Origin != adapter.Origin() || session.UserVerification != protocol.VerificationRequired || session.Challenge == "" {
		t.Fatal("encoded Passkey session lost its security boundary")
	}
	if _, err := DecodeSession(make([]byte, maximumSessionBytes+1)); err == nil {
		t.Fatal("oversized Passkey session accepted")
	}
}
