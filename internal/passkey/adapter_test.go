package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
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

func TestValidateRegistrationVerifiesAttestationAndUserBinding(t *testing.T) {
	adapter, err := New("login.example.test", "https://login.example.test:8080")
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user := &User{LocalID: 7, Handle: bytes.Repeat([]byte{0x27}, 32), Name: "registration-user", DisplayName: "Registration User"}
	options, encodedSession, err := adapter.BeginRegistration(user)
	if err != nil {
		t.Fatal(err)
	}
	if options.Response.RelyingParty.ID != adapter.RPID() || options.Response.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementRequired || options.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		t.Fatal("registration options weakened RP, discoverability or user verification")
	}
	session, err := DecodeSession(encodedSession)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := []byte("registration-credential-id")
	response := signedRegistration(t, private, adapter.RPID(), adapter.Origin(), session.Challenge, credentialID)
	result, err := adapter.ValidateRegistration(user, encodedSession, response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.CredentialID, credentialID) || len(result.PublicKey) == 0 || result.AttestationType == "" || result.AttestationFormat != "packed" || result.SignCount != 0 || result.BackupEligible || result.BackupState {
		t.Fatal("verified Passkey registration result changed")
	}
	otherPrivate, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := signedRegistrationWithSigner(t, private, otherPrivate, adapter.RPID(), adapter.Origin(), session.Challenge, credentialID)
	if _, err := adapter.ValidateRegistration(user, encodedSession, forged); err == nil {
		t.Fatal("forged Passkey registration accepted")
	}
	wrongUser := *user
	wrongUser.Handle = bytes.Repeat([]byte{0x28}, 32)
	if _, err := adapter.ValidateRegistration(&wrongUser, encodedSession, response); err == nil {
		t.Fatal("Passkey registration crossed user handle")
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

func signedRegistration(t *testing.T, private *ecdsa.PrivateKey, rpID, origin, challenge string, credentialID []byte) []byte {
	t.Helper()
	return signedRegistrationWithSigner(t, private, private, rpID, origin, challenge, credentialID)
}

func signedRegistrationWithSigner(t *testing.T, credentialPrivate, signingPrivate *ecdsa.PrivateKey, rpID, origin, challenge string, credentialID []byte) []byte {
	t.Helper()
	publicKey, err := webauthncbor.Marshal(map[int64]any{
		1: int64(webauthncose.EllipticKey), 3: int64(webauthncose.AlgES256), -1: int64(webauthncose.P256),
		-2: credentialPrivate.PublicKey.X.FillBytes(make([]byte, 32)), -3: credentialPrivate.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(rpID))
	authenticatorData := append([]byte(nil), rpHash[:]...)
	authenticatorData = append(authenticatorData, byte(protocol.FlagUserPresent|protocol.FlagUserVerified|protocol.FlagAttestedCredentialData))
	authenticatorData = binary.BigEndian.AppendUint32(authenticatorData, 0)
	authenticatorData = append(authenticatorData, make([]byte, 16)...)
	authenticatorData = binary.BigEndian.AppendUint16(authenticatorData, uint16(len(credentialID)))
	authenticatorData = append(authenticatorData, credentialID...)
	authenticatorData = append(authenticatorData, publicKey...)
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authenticatorData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(cryptorand.Reader, signingPrivate, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	attestationObject, err := webauthncbor.Marshal(map[string]any{
		"fmt": "packed", "attStmt": map[string]any{"alg": int64(webauthncose.AlgES256), "sig": signature}, "authData": authenticatorData,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	body, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
