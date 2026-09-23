package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	frameworkoidc "github.com/TheRealHZL/stumpfworks-framework/auth/oidc"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

func TestSQLiteFrameworkClientContract(t *testing.T) {
	p, st, _, _ := testProvider(t)
	testFrameworkClientContract(t, p, st)
}

type frameworkIdentityReader interface {
	UserByUsername(context.Context, string) (database.User, error)
}

func testFrameworkClientContract(t *testing.T, p *Provider, store frameworkIdentityReader) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	p.now = time.Now
	mux := http.NewServeMux()
	p.Register(mux)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	p.issuer = server.URL
	transport := server.Client()
	transport.Timeout = 5 * time.Second
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	configuration, err := frameworkoidc.Discover(ctx, server.URL, "stumpfworks-access", transport)
	if err != nil {
		t.Fatal("framework discovery of actual Identity handlers failed")
	}
	client, err := frameworkoidc.NewLoginClient(configuration, "stumpfworks-access", "client-secret", "https://access.example.test/api/v1/auth/oidc/callback", transport)
	if err != nil {
		t.Fatal("framework login client failed")
	}
	address, transaction, err := client.Begin()
	if err != nil {
		t.Fatal("framework login begin failed")
	}
	authorization, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	form := authorization.Query()
	form.Set("username", "alice")
	form.Set("password", "correct")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/oauth2/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := transport.Do(request)
	if err != nil {
		t.Fatal("local TLS authorization request failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatal("Identity authorization did not redirect")
	}
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || callback.Scheme != "https" || callback.Host != "access.example.test" || callback.Path != "/api/v1/auth/oidc/callback" {
		t.Fatal("unexpected callback origin/path")
	}
	pending, err := frameworkoidc.NewTransactionStore(8)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := frameworkoidc.NewBrowserBinding()
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Put(transaction, binding); err != nil {
		t.Fatal("browser transaction storage failed")
	}
	taken, err := pending.Take(callback.Query().Get("state"), binding)
	if err != nil {
		t.Fatal("browser-bound callback lookup failed")
	}
	identity, err := taken.Complete(ctx, callback.Query())
	if err != nil {
		t.Fatal("framework confidential PKCE exchange failed")
	}
	user, err := store.UserByUsername(ctx, "alice")
	if err != nil || identity.Issuer != server.URL || identity.Subject != user.OIDCSubject || identity.Subject == "alice" {
		t.Fatal("framework external identity mapping changed")
	}
	if _, err := taken.Complete(ctx, callback.Query()); err == nil {
		t.Fatal("framework callback replay accepted")
	}
}
