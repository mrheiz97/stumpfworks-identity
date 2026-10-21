package passkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/x/crypto/secp256k1"
	secp256k1ecdsa "github.com/go-webauthn/x/crypto/secp256k1/ecdsa"
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

func TestValidateDiscoverableLoginVerifiesAssertionAndResolvedUser(t *testing.T) {
	adapter, err := New("login.example.test", "https://login.example.test:8080")
	if err != nil {
		t.Fatal(err)
	}
	_, encodedSession, err := adapter.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	session, err := DecodeSession(encodedSession)
	if err != nil {
		t.Fatal(err)
	}
	private, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	credentialID := []byte("adapter-credential-id")
	userHandle := bytes.Repeat([]byte{0x42}, 32)
	public := private.PubKey()
	publicKey, err := webauthncbor.Marshal(map[int64]any{
		1: int64(webauthncose.EllipticKey), 3: int64(webauthncose.AlgES256K), -1: int64(webauthncose.Secp256k1),
		-2: public.X().FillBytes(make([]byte, 32)), -3: public.Y().FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertion := signedAssertion(t, private, adapter.RPID(), adapter.Origin(), session.Challenge, credentialID, userHandle, 1)
	lookup := func(rawID, handle []byte) (*User, error) {
		if !bytes.Equal(rawID, credentialID) || !bytes.Equal(handle, userHandle) {
			t.Fatal("adapter changed discoverable lookup identifiers")
		}
		return &User{LocalID: 42, Handle: userHandle, Name: "passkey-user", DisplayName: "Passkey User", Credentials: []Credential{{ID: credentialID, PublicKey: publicKey, Flags: byte(protocol.FlagUserPresent | protocol.FlagUserVerified), SignCount: 0}}}, nil
	}
	result, err := adapter.ValidateDiscoverableLogin(encodedSession, assertion, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalUserID != 42 || !bytes.Equal(result.CredentialID, credentialID) || result.SignCount != 1 || result.BackupState {
		t.Fatal("verified Passkey assertion result changed")
	}
	otherPrivate, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	forged := signedAssertion(t, otherPrivate, adapter.RPID(), adapter.Origin(), session.Challenge, credentialID, userHandle, 2)
	if _, err := adapter.ValidateDiscoverableLogin(encodedSession, forged, lookup); err == nil {
		t.Fatal("tampered Passkey assertion accepted")
	}
	if _, err := adapter.ValidateDiscoverableLogin(encodedSession, make([]byte, maximumAssertionBytes+1), lookup); err == nil {
		t.Fatal("oversized Passkey assertion accepted")
	}
}

func signedAssertion(t *testing.T, private *secp256k1.PrivateKey, rpID, origin, challenge string, credentialID, userHandle []byte, signCount uint32) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	authenticatorData := append([]byte(nil), rpHash[:]...)
	authenticatorData = append(authenticatorData, byte(protocol.FlagUserPresent|protocol.FlagUserVerified))
	authenticatorData = binary.BigEndian.AppendUint32(authenticatorData, signCount)
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authenticatorData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature := secp256k1ecdsa.Sign(private, digest[:]).Serialize()
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	body, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authenticatorData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userHandle),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
