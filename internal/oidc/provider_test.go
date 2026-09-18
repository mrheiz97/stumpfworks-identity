package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/bcrypt"
)

type testDirectory struct{ disabled bool }

func (d *testDirectory) UserExists(context.Context, string) (bool, error) { return !d.disabled, nil }
func (d *testDirectory) GetUser(_ context.Context, u string) (*directory.User, error) {
	if d.disabled {
		return nil, directory.ErrUserNotFound
	}
	return &directory.User{Username: u, DisplayName: "Alice Example", Mail: "alice@example.test"}, nil
}
func (d *testDirectory) ListUsers(context.Context) ([]directory.User, error) { return nil, nil }
func (d *testDirectory) AuthenticateUser(_ context.Context, u, p string) (*directory.User, error) {
	if d.disabled || u != "alice" || p != "correct" {
		return nil, directory.ErrInvalidCredentials
	}
	return &directory.User{Username: u, DisplayName: "Alice Example", DN: "CN=Alice", Mail: "alice@example.test"}, nil
}
func (d *testDirectory) AuthenticateAdmin(context.Context, string, string) (*directory.User, error) {
	return nil, directory.ErrNotAuthorized
}

func testProvider(t *testing.T) (*Provider, *database.Store, *rsa.PrivateKey, *testDirectory) {
	t.Helper()
	st, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	dir := &testDirectory{}
	sessions, _ := adminauth.NewSessions(strings.Repeat("s", 32), time.Hour)
	p, err := New("https://identity.example.test", []string{path}, st, dir, sessions)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("client-secret"), bcrypt.MinCost)
	if err = st.UpsertOIDCClient(t.Context(), "stumpfworks-access", string(hash), "https://access.example.test/api/v1/auth/oidc/callback", "openid profile email"); err != nil {
		t.Fatal(err)
	}
	return p, st, key, dir
}
func serve(p *Provider, r *http.Request) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	p.Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}
func authValues(verifier string) url.Values {
	sum := sha256.Sum256([]byte(verifier))
	return url.Values{"response_type": {"code"}, "client_id": {"stumpfworks-access"}, "redirect_uri": {"https://access.example.test/api/v1/auth/oidc/callback"}, "scope": {"openid profile email"}, "state": {"state-1"}, "nonce": {"nonce-1"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
}

func TestAuthorizationFormAllowsOnlyRegisteredCallbackOrigin(t *testing.T) {
	p, _, _, _ := testProvider(t)
	v := authValues(strings.Repeat("v", 43))
	w := serve(p, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+v.Encode(), nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self' https://access.example.test;") {
		t.Fatalf("registered callback not allowed: status=%d CSP=%q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
	v.Set("redirect_uri", "https://attacker.example/callback")
	w = serve(p, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+v.Encode(), nil))
	if w.Code != http.StatusBadRequest || strings.Contains(w.Header().Get("Content-Security-Policy"), "attacker.example") {
		t.Fatal("unregistered callback affected form policy")
	}
}
func issueCode(t *testing.T, p *Provider, verifier string) string {
	t.Helper()
	v := authValues(verifier)
	v.Set("username", "alice")
	v.Set("password", "correct")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serve(p, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("authorize=%d %s", w.Code, w.Body.String())
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Query().Get("state") != "state-1" {
		t.Fatal("state not preserved")
	}
	return u.Query().Get("code")
}
func exchange(p *Provider, code, verifier string) *httptest.ResponseRecorder {
	return exchangeSecret(p, code, verifier, "client-secret")
}
func exchangeSecret(p *Provider, code, verifier, secret string) *httptest.ResponseRecorder {
	return exchangeFrom(p, code, verifier, secret, "")
}
func exchangeFrom(p *Provider, code, verifier, secret, remoteAddress string) *httptest.ResponseRecorder {
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://access.example.test/api/v1/auth/oidc/callback"}, "code_verifier": {verifier}}
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(v.Encode()))
	if remoteAddress != "" {
		r.RemoteAddr = remoteAddress
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("stumpfworks-access", secret)
	return serve(p, r)
}

func TestAuthorizationAndTokenFailures(t *testing.T) {
	p, _, _, _ := testProvider(t)
	v := authValues(strings.Repeat("v", 43))
	v.Del("code_challenge_method")
	if w := serve(p, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+v.Encode(), nil)); w.Code != 400 {
		t.Fatalf("authorization without S256 accepted: %d", w.Code)
	}
	v = authValues(strings.Repeat("v", 43))
	v.Set("client_id", "unknown")
	if w := serve(p, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+v.Encode(), nil)); w.Code != 400 {
		t.Fatalf("unknown client accepted: %d", w.Code)
	}
	code := issueCode(t, p, strings.Repeat("v", 43))
	if w := exchangeSecret(p, code, strings.Repeat("v", 43), "wrong"); w.Code != 401 {
		t.Fatalf("wrong client secret accepted: %d", w.Code)
	}
}

func TestTokenRateLimit(t *testing.T) {
	p, _, _, _ := testProvider(t)
	testTokenRateLimit(t, p)
}

func testTokenRateLimit(t *testing.T, p *Provider) {
	t.Helper()
	const remoteAddress = "192.0.2.99:1234"
	for i := 0; i < 10; i++ {
		if response := exchangeFrom(p, "synthetic-unused", strings.Repeat("v", 43), "wrong", remoteAddress); response.Code != 401 {
			t.Fatal("client rejected before rate threshold")
		}
	}
	if response := exchangeFrom(p, "synthetic-unused", strings.Repeat("v", 43), "wrong", remoteAddress); response.Code != 429 {
		t.Fatal("token rate threshold not enforced")
	}
}

func TestExpiredCode(t *testing.T) {
	p, _, _, _ := testProvider(t)
	clock := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return clock }
	verifier := strings.Repeat("v", 43)
	code := issueCode(t, p, verifier)
	clock = clock.Add(91 * time.Second)
	if w := exchange(p, code, verifier); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("expired code accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestOverlappingSigningKeys(t *testing.T) {
	p, st, _, dir := testProvider(t)
	oldKey := p.keys[0]
	newPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newDER, _ := x509.MarshalPKCS8PrivateKey(newPrivate)
	newPath := filepath.Join(t.TempDir(), "new.pem")
	if err = os.WriteFile(newPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: newDER}), 0600); err != nil {
		t.Fatal(err)
	}
	oldPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oldDER, _ := x509.MarshalPKCS8PrivateKey(oldPrivate)
	oldPath := filepath.Join(t.TempDir(), "old.pem")
	if err = os.WriteFile(oldPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: oldDER}), 0600); err != nil {
		t.Fatal(err)
	}
	sessions, _ := adminauth.NewSessions(strings.Repeat("s", 32), time.Hour)
	rotated, err := New("https://identity.example.test", []string{newPath, oldPath}, st, dir, sessions)
	if err != nil {
		t.Fatal(err)
	}
	w := serve(rotated, httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil))
	var set jose.JSONWebKeySet
	if err = json.Unmarshal(w.Body.Bytes(), &set); err != nil || len(set.Keys) != 2 || set.Keys[0].KeyID == set.Keys[1].KeyID || oldKey.KeyID == "" {
		t.Fatalf("bad overlapping JWKS: %+v %v", set, err)
	}
}

func TestDiscoveryAndAuthorizationCodePKCE(t *testing.T) {
	p, _, key, _ := testProvider(t)
	w := serve(p, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code_challenge_methods_supported":["S256"]`) {
		t.Fatal(w.Code, w.Body.String())
	}
	verifier := strings.Repeat("v", 43)
	code := issueCode(t, p, verifier)
	w = exchange(p, code, verifier)
	if w.Code != 200 {
		t.Fatalf("token=%d %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	raw := out["id_token"].(string)
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err = parsed.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "https://identity.example.test" || claims["sub"] == "alice" || claims["nonce"] != "nonce-1" {
		t.Fatalf("bad claims: %#v", claims)
	}
	if replay := exchange(p, code, verifier); replay.Code != 400 || !strings.Contains(replay.Body.String(), "invalid_grant") {
		t.Fatalf("replay accepted: %d %s", replay.Code, replay.Body.String())
	}
}
func TestRejectsRedirectPKCEAndDisabledUser(t *testing.T) {
	p, _, _, dir := testProvider(t)
	v := authValues(strings.Repeat("v", 43))
	v.Set("redirect_uri", "https://evil.example/callback")
	w := serve(p, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+v.Encode(), nil))
	if w.Code != 400 {
		t.Fatalf("redirect accepted: %d", w.Code)
	}
	code := issueCode(t, p, strings.Repeat("v", 43))
	if bad := exchange(p, code, strings.Repeat("x", 43)); bad.Code != 400 {
		t.Fatalf("bad PKCE accepted: %d", bad.Code)
	}
	code = issueCode(t, p, strings.Repeat("v", 43))
	dir.disabled = true
	if disabled := exchange(p, code, strings.Repeat("v", 43)); disabled.Code != 400 {
		body, _ := io.ReadAll(disabled.Result().Body)
		t.Fatalf("disabled user accepted: %d %s", disabled.Code, body)
	}
}
func TestStableOpaqueSubject(t *testing.T) {
	_, st, _, _ := testProvider(t)
	u, err := st.CreateUser(t.Context(), "alice", "Alice", "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.EnsureOIDCSubject(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB.Exec(`UPDATE users SET username='renamed',display_name='Renamed' WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	second, err := st.EnsureOIDCSubject(t.Context(), u.ID)
	if err != nil || first != second || first == "alice" {
		t.Fatalf("subject changed: %q %q %v", first, second, err)
	}
}
