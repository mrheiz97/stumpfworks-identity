package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/bcrypt"
)

type Provider struct {
	issuer   string
	store    providerStore
	dir      directory.Directory
	sessions *adminauth.Sessions
	keys     []jose.JSONWebKey
	signer   jose.Signer
	now      func() time.Time
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func New(issuer string, keyFiles []string, store *database.Store, dir directory.Directory, sessions *adminauth.Sessions) (*Provider, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("OIDC issuer must be an exact HTTPS origin")
	}
	if len(keyFiles) == 0 {
		return nil, errors.New("at least one OIDC signing key is required")
	}
	p := &Provider{issuer: issuer, store: store, dir: dir, sessions: sessions, now: time.Now, attempts: map[string][]time.Time{}}
	for _, file := range keyFiles {
		key, err := loadRSAKey(strings.TrimSpace(file))
		if err != nil {
			return nil, fmt.Errorf("load OIDC key: %w", err)
		}
		der := x509.MarshalPKCS1PublicKey(&key.PublicKey)
		sum := sha256.Sum256(der)
		kid := hex.EncodeToString(sum[:8])
		p.keys = append(p.keys, jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"})
		if p.signer == nil {
			p.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
			if err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}
func loadRSAKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := k.(*rsa.PrivateKey); ok && rsaKey.N.BitLen() >= 2048 {
			return rsaKey, nil
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil && k.N.BitLen() >= 2048 {
		return k, nil
	}
	return nil, errors.New("signing key must be an RSA private key of at least 2048 bits")
}

func (p *Provider) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /oauth2/authorize", p.authorize)
	mux.HandleFunc("POST /oauth2/authorize", p.authorize)
	mux.HandleFunc("POST /oauth2/token", p.token)
	mux.HandleFunc("GET /oauth2/jwks", p.jwks)
}
func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.writeJSON(w, 200, map[string]any{"issuer": p.issuer, "authorization_endpoint": p.issuer + "/oauth2/authorize", "token_endpoint": p.issuer + "/oauth2/token", "jwks_uri": p.issuer + "/oauth2/jwks", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "scopes_supported": []string{"openid", "profile", "email"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}})
}
func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	p.writeJSON(w, 200, jose.JSONWebKeySet{Keys: p.keys})
}

type request struct{ ClientID, RedirectURI, Scope, State, Nonce, Challenge string }

func (p *Provider) validate(r *http.Request) (request, database.OIDCClient, error) {
	q := r.Form
	a := request{q.Get("client_id"), q.Get("redirect_uri"), q.Get("scope"), q.Get("state"), q.Get("nonce"), q.Get("code_challenge")}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || a.State == "" || len(a.State) > 512 || a.Nonce == "" || len(a.Nonce) > 256 {
		return a, database.OIDCClient{}, errors.New("invalid_request")
	}
	c, err := p.store.OIDCClientByID(r.Context(), a.ClientID)
	if err != nil || !c.Enabled {
		return a, c, errors.New("unauthorized_client")
	}
	if !slices.Contains(strings.Split(c.RedirectURIs, "\n"), a.RedirectURI) {
		return a, c, errors.New("redirect_uri_mismatch")
	}
	allowed := strings.Fields(c.Scopes)
	requested := strings.Fields(a.Scope)
	if len(requested) == 0 || !slices.Contains(requested, "openid") {
		return a, c, errors.New("invalid_scope")
	}
	for _, s := range requested {
		if !slices.Contains(allowed, s) {
			return a, c, errors.New("invalid_scope")
		}
	}
	if len(a.Challenge) < 43 || len(a.Challenge) > 128 {
		return a, c, errors.New("invalid_request")
	}
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(a.Challenge)
	if decodeErr != nil || len(decoded) != sha256.Size {
		return a, c, errors.New("invalid_request")
	}
	return a, c, nil
}
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	a, _, err := p.validate(r)
	if err != nil {
		p.audit(r, "oidc_authorization_denied", "", a.ClientID, false, err.Error())
		http.Error(w, err.Error(), 400)
		return
	}
	if r.Method == http.MethodGet {
		// Chromium also applies form-action to redirects after form submission.
		// Only the origin of the already validated, registered callback is allowed.
		callback, _ := url.Parse(a.RedirectURI)
		if strings.ContainsAny(callback.Host, " \t\r\n;'*") {
			http.Error(w, "invalid callback origin", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self' "+callback.Scheme+"://"+callback.Host+"; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = authTemplate.Execute(w, map[string]string{"ClientID": a.ClientID, "RedirectURI": a.RedirectURI, "Scope": a.Scope, "State": a.State, "Nonce": a.Nonce, "Challenge": a.Challenge})
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if !p.allowed("oidc:" + remoteIP(r)) {
		p.audit(r, "oidc_login_denied", username, a.ClientID, false, "rate_limited")
		http.Error(w, "rate limited", 429)
		return
	}
	u, err := p.dir.AuthenticateUser(r.Context(), username, r.FormValue("password"))
	if err != nil {
		p.audit(r, "oidc_login_denied", username, a.ClientID, false, "invalid_credentials")
		http.Error(w, "invalid credentials", 401)
		return
	}
	local, err := p.store.UserByUsername(r.Context(), u.Username)
	if errors.Is(err, context.Canceled) {
		http.Error(w, "unavailable", 503)
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "unavailable", 503)
		return
	}
	if err != nil {
		local, err = p.store.CreateUser(r.Context(), u.Username, u.DisplayName, u.DN)
	}
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	if _, err = p.store.EnsureOIDCSubject(r.Context(), local.ID); err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	code := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(code))
	err = p.store.CreateOIDCCode(r.Context(), database.OIDCCode{CodeHash: hex.EncodeToString(sum[:]), ClientID: a.ClientID, UserID: local.ID, RedirectURI: a.RedirectURI, Scope: a.Scope, Nonce: a.Nonce, CodeChallenge: a.Challenge, ExpiresAt: p.now().Add(90 * time.Second)})
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	p.audit(r, "oidc_login", local.Username, a.ClientID, true, "")
	p.audit(r, "oidc_consent", local.Username, a.ClientID, true, a.Scope)
	p.audit(r, "oidc_code_issued", local.Username, a.ClientID, true, "")
	dest, _ := url.Parse(a.RedirectURI)
	q := dest.Query()
	q.Set("code", code)
	if a.State != "" {
		q.Set("state", a.State)
	}
	dest.RawQuery = q.Encode()
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if !p.allowed("oidc-token:" + remoteIP(r)) {
		p.oauthError(w, "temporarily_unavailable", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		p.oauthError(w, "invalid_request", 400)
		return
	}
	if r.FormValue("grant_type") != "authorization_code" {
		p.oauthError(w, "unsupported_grant_type", 400)
		return
	}
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		secret = r.FormValue("client_secret")
	}
	c, err := p.store.OIDCClientByID(r.Context(), clientID)
	if err != nil || !c.Enabled || bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(secret)) != nil {
		p.audit(r, "oidc_token_denied", "", clientID, false, "invalid_client")
		p.oauthError(w, "invalid_client", 401)
		return
	}
	code := r.FormValue("code")
	sum := sha256.Sum256([]byte(code))
	stored, err := p.store.ConsumeOIDCCode(r.Context(), hex.EncodeToString(sum[:]), clientID, r.FormValue("redirect_uri"), p.now())
	if err != nil {
		p.audit(r, "oidc_token_denied", "", clientID, false, "invalid_grant")
		p.oauthError(w, "invalid_grant", 400)
		return
	}
	verifier := r.FormValue("code_verifier")
	if len(verifier) < 43 || len(verifier) > 128 {
		p.audit(r, "oidc_token_denied", "", clientID, false, "pkce_failed")
		p.oauthError(w, "invalid_grant", 400)
		return
	}
	challenge := sha256.Sum256([]byte(verifier))
	if verifier == "" || base64.RawURLEncoding.EncodeToString(challenge[:]) != stored.CodeChallenge {
		p.audit(r, "oidc_token_denied", "", clientID, false, "pkce_failed")
		p.oauthError(w, "invalid_grant", 400)
		return
	}
	u, err := p.store.GetUser(r.Context(), stored.UserID)
	if err != nil {
		p.oauthError(w, "invalid_grant", 400)
		return
	}
	du, err := p.dir.GetUser(r.Context(), u.Username)
	if err != nil {
		p.audit(r, "oidc_token_denied", u.Username, clientID, false, "user_inactive")
		p.oauthError(w, "invalid_grant", 400)
		return
	}
	sub, err := p.store.EnsureOIDCSubject(r.Context(), u.ID)
	if err != nil {
		p.oauthError(w, "server_error", 500)
		return
	}
	now := p.now().UTC()
	claims := map[string]any{"iss": p.issuer, "sub": sub, "aud": clientID, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": stored.Nonce}
	if strings.Contains(" "+stored.Scope+" ", " profile ") {
		claims["name"] = u.DisplayName
		claims["preferred_username"] = u.Username
	}
	if strings.Contains(" "+stored.Scope+" ", " email ") && du.Mail != "" {
		claims["email"] = du.Mail
	}
	idToken, err := jwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		p.oauthError(w, "server_error", 500)
		return
	}
	accessRaw := make([]byte, 32)
	if _, err = rand.Read(accessRaw); err != nil {
		p.oauthError(w, "server_error", 500)
		return
	}
	p.audit(r, "oidc_token_issued", u.Username, clientID, true, "")
	p.writeJSON(w, 200, map[string]any{"access_token": base64.RawURLEncoding.EncodeToString(accessRaw), "token_type": "Bearer", "expires_in": 300, "id_token": idToken, "scope": stored.Scope})
}

func (p *Provider) audit(r *http.Request, event, user, client string, success bool, details string) {
	p.store.Audit(r.Context(), event, "", user, client, success, remoteIP(r), details)
}
func (p *Provider) allowed(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	cut := now.Add(-10 * time.Minute)
	kept := p.attempts[key][:0]
	for _, t := range p.attempts[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 10 {
		p.attempts[key] = kept
		return false
	}
	p.attempts[key] = append(kept, now)
	return true
}
func (p *Provider) oauthError(w http.ResponseWriter, code string, status int) {
	p.writeJSON(w, status, map[string]string{"error": code})
}
func (p *Provider) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var authTemplate = template.Must(template.New("oidc").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Authorize Access — StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body class="login-page"><main class="self-shell"><header class="self-header"><a class="brand" href="/"><span class="brand-mark">S</span><span><strong>StumpfWorks</strong><small>Identity Platform</small></span></a><span class="status-chip"><i></i>Secure connection</span></header><section class="self-card"><div class="login-icon">◇</div><p class="eyebrow">APPLICATION SIGN-IN</p><h1>Sign in to StumpfWorks Access</h1><p class="self-intro">Identity confirms who you are. Access keeps all physical access rights and permissions.</p><div class="identity-row"><span class="avatar">◇</span><span><strong>StumpfWorks Access</strong><small>Verified OIDC client · {{.ClientID}}</small></span><span class="badge success">openid</span></div><form class="login-form" method="post"><input type="hidden" name="response_type" value="code"><input type="hidden" name="client_id" value="{{.ClientID}}"><input type="hidden" name="redirect_uri" value="{{.RedirectURI}}"><input type="hidden" name="scope" value="{{.Scope}}"><input type="hidden" name="state" value="{{.State}}"><input type="hidden" name="nonce" value="{{.Nonce}}"><input type="hidden" name="code_challenge" value="{{.Challenge}}"><input type="hidden" name="code_challenge_method" value="S256"><label><span>AD username</span><input name="username" autocomplete="username" placeholder="Your domain username" required autofocus></label><label><span>AD password</span><input type="password" name="password" autocomplete="current-password" placeholder="Your current password" required></label><button type="submit">Sign in and authorize</button></form><p class="privacy">Your password is verified over LDAPS, never stored, and never shared with Access.</p></section></main></body></html>`))
