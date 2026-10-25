package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	passkeyauth "github.com/TheRealHZL/stumpfworks-identity/internal/passkey"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestPasskeySelfServiceEndToEnd(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	user, err := store.CreateUser(t.Context(), "alice", "Alice Example", "CN=Alice Example,DC=example")
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := adminauth.NewSessions("01234567890123456789012345678901", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := NewProtected(store, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeDirectory{}, sessions)
	adapter, err := passkeyauth.New("login.example.test", "https://login.example.test:8080")
	if err != nil || server.ConfigurePasskeys(adapter) != nil {
		t.Fatal("Passkey integration configuration failed")
	}
	now := time.Now().UTC()
	currentSessionID := "password-session"
	if err := store.CreateSelfServiceSession(t.Context(), currentSessionID, user.Username, now.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	currentToken := sessions.IssueForDuration("self-service", user.Username+"\x1f"+currentSessionID, now, 15*time.Minute)
	currentCookie := &http.Cookie{Name: "swbadge_selfservice", Value: currentToken, Path: "/self-service"}
	csrf := sessions.CSRF(currentToken)

	beginRegistration := passkeyRequest(t, server, "/self-service/passkeys/registration/begin", map[string]string{"password": "correct"}, currentCookie, csrf)
	if beginRegistration.Code != http.StatusOK {
		t.Fatalf("registration begin failed: %d %s", beginRegistration.Code, beginRegistration.Body.String())
	}
	var registrationOptions struct {
		CeremonyID string `json:"ceremony_id"`
		PublicKey  struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(beginRegistration.Body.Bytes(), &registrationOptions); err != nil || registrationOptions.CeremonyID == "" || registrationOptions.PublicKey.Challenge == "" {
		t.Fatal("registration options were incomplete")
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := []byte("server-e2e-passkey-credential")
	registrationResponse := serverRegistrationResponse(t, private, adapter.RPID(), adapter.Origin(), registrationOptions.PublicKey.Challenge, credentialID)
	completeRegistration := passkeyRequest(t, server, "/self-service/passkeys/registration/complete", map[string]any{"ceremony_id": registrationOptions.CeremonyID, "name": "Test Passkey", "response": json.RawMessage(registrationResponse)}, currentCookie, csrf)
	if completeRegistration.Code != http.StatusOK {
		t.Fatalf("registration completion failed: %d %s", completeRegistration.Code, completeRegistration.Body.String())
	}
	credentials, err := store.WebAuthnCredentialsByUser(t.Context(), user.ID)
	if err != nil || len(credentials) != 1 || !bytes.Equal(credentials[0].CredentialID, credentialID) {
		t.Fatal("registered credential was not persisted")
	}

	beginLogin := passkeyRequest(t, server, "/self-service/passkeys/login/begin", struct{}{}, nil, "")
	if beginLogin.Code != http.StatusOK {
		t.Fatalf("login begin failed: %d %s", beginLogin.Code, beginLogin.Body.String())
	}
	var loginOptions struct {
		CeremonyID string `json:"ceremony_id"`
		PublicKey  struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(beginLogin.Body.Bytes(), &loginOptions); err != nil || loginOptions.CeremonyID == "" || loginOptions.PublicKey.Challenge == "" {
		t.Fatal("login options were incomplete")
	}
	handle, err := store.EnsureWebAuthnUserHandle(t.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertion := serverAssertionResponse(t, private, adapter.RPID(), adapter.Origin(), loginOptions.PublicKey.Challenge, credentialID, handle, 1)
	loginBody := map[string]any{"ceremony_id": loginOptions.CeremonyID, "response": json.RawMessage(assertion)}
	completeLogin := passkeyRequest(t, server, "/self-service/passkeys/login/complete", loginBody, nil, "")
	if completeLogin.Code != http.StatusOK || len(completeLogin.Result().Cookies()) != 1 || completeLogin.Result().Cookies()[0].Name != "swbadge_selfservice" {
		t.Fatalf("Passkey login did not issue the Self-Service cookie: %d", completeLogin.Code)
	}
	replay := passkeyRequest(t, server, "/self-service/passkeys/login/complete", loginBody, nil, "")
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("Passkey replay returned %d", replay.Code)
	}
	audits, err := store.Audits(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, audit := range audits {
		counts[audit.EventType]++
		if (audit.EventType == "passkey_registered" || audit.EventType == "passkey_login") && audit.Details != "" {
			t.Fatal("Passkey success audit contained details")
		}
	}
	if counts["passkey_registered"] != 1 || counts["passkey_login"] != 1 {
		t.Fatalf("unexpected Passkey audit counts: %+v", counts)
	}
}

func passkeyRequest(t *testing.T, server *Server, path string, payload any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func serverRegistrationResponse(t *testing.T, private *ecdsa.PrivateKey, rpID, origin, challenge string, credentialID []byte) []byte {
	t.Helper()
	publicKey, err := webauthncbor.Marshal(map[int64]any{
		1: int64(webauthncose.EllipticKey), 3: int64(webauthncose.AlgES256), -1: int64(webauthncose.P256),
		-2: private.PublicKey.X.FillBytes(make([]byte, 32)), -3: private.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte(nil), rpHash[:]...)
	authData = append(authData, byte(protocol.FlagUserPresent|protocol.FlagUserVerified|protocol.FlagAttestedCredentialData))
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, publicKey...)
	clientData := serverClientData(t, "webauthn.create", challenge, origin)
	signature := serverSign(t, private, authData, clientData)
	attestation, err := webauthncbor.Marshal(map[string]any{"fmt": "packed", "attStmt": map[string]any{"alg": int64(webauthncose.AlgES256), "sig": signature}, "authData": authData})
	if err != nil {
		t.Fatal(err)
	}
	return serverCredentialJSON(t, credentialID, map[string]any{"attestationObject": base64.RawURLEncoding.EncodeToString(attestation), "clientDataJSON": base64.RawURLEncoding.EncodeToString(clientData)})
}

func serverAssertionResponse(t *testing.T, private *ecdsa.PrivateKey, rpID, origin, challenge string, credentialID, handle []byte, count uint32) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte(nil), rpHash[:]...)
	authData = append(authData, byte(protocol.FlagUserPresent|protocol.FlagUserVerified))
	authData = binary.BigEndian.AppendUint32(authData, count)
	clientData := serverClientData(t, "webauthn.get", challenge, origin)
	signature := serverSign(t, private, authData, clientData)
	return serverCredentialJSON(t, credentialID, map[string]any{"authenticatorData": base64.RawURLEncoding.EncodeToString(authData), "clientDataJSON": base64.RawURLEncoding.EncodeToString(clientData), "signature": base64.RawURLEncoding.EncodeToString(signature), "userHandle": base64.RawURLEncoding.EncodeToString(handle)})
}

func serverClientData(t *testing.T, ceremony, challenge, origin string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"type": ceremony, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func serverSign(t *testing.T, private *ecdsa.PrivateKey, authData, clientData []byte) []byte {
	t.Helper()
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func serverCredentialJSON(t *testing.T, credentialID []byte, response map[string]any) []byte {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	data, err := json.Marshal(map[string]any{"id": id, "rawId": id, "type": "public-key", "response": response})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
