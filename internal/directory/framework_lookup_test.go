package directory

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	frameworkldap "github.com/TheRealHZL/stumpfworks-framework/directory/ldap"
)

func TestLDAPFrameworkConfigurationBoundary(t *testing.T) {
	base := LDAP{URL: "ldaps://directory.example.test", BaseDN: "DC=example,DC=test", BindDN: "CN=service,DC=example,DC=test", BindPassword: "synthetic", Domain: "EXAMPLE", AdminGroupDN: "CN=admins,DC=example,DC=test"}
	pinned := base
	pinned.CertSHA256 = "synthetic-legacy-pin"
	if _, err := pinned.WithFrameworkLookups(); err == nil {
		t.Fatal("legacy TLS exception accepted")
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for _, tc := range []struct {
		name, contents string
		valid          bool
	}{
		{"valid", string(validPEM), true},
		{"invalid", "not a certificate", false},
		{"oversized", strings.Repeat("x", (1<<20)+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.CAFile = filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(d.CAFile, []byte(tc.contents), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := d.WithFrameworkLookups()
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid CA file accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			overlay := result.(*lookupOverlay)
			if overlay.Directory.(LDAP) != d {
				t.Fatal("authentication directory configuration changed")
			}
		})
	}
	missing := base
	missing.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := missing.WithFrameworkLookups(); err == nil {
		t.Fatal("missing CA silently ignored")
	}
	if _, err := base.WithFrameworkLookups(); err != nil {
		t.Fatal("system-root configuration rejected")
	}
}

type frameworkReaderFunc func(context.Context, string) (*frameworkldap.User, error)

func (f frameworkReaderFunc) GetUser(ctx context.Context, name string) (*frameworkldap.User, error) {
	return f(ctx, name)
}

func TestFrameworkLookupProjectionAndPolicyBoundary(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{}{}, "request")
	called := 0
	lookup := frameworkUserLookup(frameworkReaderFunc(func(got context.Context, name string) (*frameworkldap.User, error) {
		called++
		if got != ctx || name != "alice" {
			t.Fatal("request context or username changed")
		}
		return &frameworkldap.User{Username: "alice", DisplayName: "Alice", DN: "CN=Alice,DC=example,DC=test", Mail: "alice@example.test"}, nil
	}))
	d, err := WithUserLookup(Local{}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	u, err := d.GetUser(ctx, "alice")
	if err != nil || *u != (User{Username: "alice", DisplayName: "Alice", DN: "CN=Alice,DC=example,DC=test", Mail: "alice@example.test"}) {
		t.Fatal("user projection changed")
	}
	if _, err := d.AuthenticateUser(ctx, "alice", "synthetic"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticateAdmin(ctx, "alice", "synthetic"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ListUsers(ctx); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatal("framework reader received authentication or listing")
	}
}

func TestFrameworkLookupFailureMapping(t *testing.T) {
	for _, failure := range []error{frameworkldap.ErrNotFound, frameworkldap.ErrAmbiguous, frameworkldap.ErrUnavailable, context.Canceled, context.DeadlineExceeded} {
		t.Run(failure.Error(), func(t *testing.T) {
			d, _ := WithUserLookup(Local{}, frameworkUserLookup(frameworkReaderFunc(func(context.Context, string) (*frameworkldap.User, error) { return nil, failure })))
			_, err := d.GetUser(context.Background(), "alice")
			want := failure
			if failure == frameworkldap.ErrNotFound {
				want = ErrUserNotFound
			}
			if !errors.Is(err, want) {
				t.Fatal("error mapping changed")
			}
			exists, err := d.UserExists(context.Background(), "alice")
			if exists {
				t.Fatal("lookup failure reported existing user")
			}
			if failure == frameworkldap.ErrNotFound {
				if err != nil {
					t.Fatal("missing user became infrastructure failure")
				}
			} else if !errors.Is(err, failure) {
				t.Fatal("infrastructure failure swallowed")
			}
		})
	}
}

func TestFrameworkLookupConstructorAndCanceledReader(t *testing.T) {
	if _, err := WithFrameworkUserLookup(Local{}, frameworkldap.Config{URL: "ldap://example.test"}); err == nil {
		t.Fatal("plaintext configuration accepted")
	}
	config := frameworkldap.Config{URL: "ldaps://directory.example.test", BaseDN: "DC=example,DC=test", BindDN: "CN=service,DC=example,DC=test", BindPassword: "synthetic"}
	if _, err := WithFrameworkUserLookup(nil, config); err == nil {
		t.Fatal("missing existing adapter accepted")
	}
	d, err := WithFrameworkUserLookup(Local{}, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.GetUser(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not preserved")
	}
	for _, invalid := range []*frameworkldap.User{nil, {DisplayName: "missing username"}} {
		lookup := frameworkUserLookup(frameworkReaderFunc(func(context.Context, string) (*frameworkldap.User, error) { return invalid, nil }))
		if _, err := lookup(context.Background(), "alice"); err == nil {
			t.Fatal("invalid reader result accepted")
		}
	}
}
