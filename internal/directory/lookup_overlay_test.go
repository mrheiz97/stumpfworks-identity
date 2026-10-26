package directory

import (
	"context"
	"errors"
	"testing"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
)

type administrativeTestDirectory struct{ Local }

func (administrativeTestDirectory) AdministrativeRoles(context.Context, string) ([]adminauth.Role, error) {
	return []adminauth.Role{adminauth.RoleAuditor}, nil
}

func (administrativeTestDirectory) AuthenticateAdministrative(_ context.Context, username, _ string) (*User, []adminauth.Role, error) {
	return &User{Username: username}, []adminauth.Role{adminauth.RoleAuditor}, nil
}

func TestLookupOverlayBoundary(t *testing.T) {
	called := false
	d, err := WithUserLookup(Local{}, func(_ context.Context, name string) (*User, error) {
		called = true
		return &User{Username: name, DisplayName: "Framework result"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := d.GetUser(context.Background(), "alice")
	if err != nil || !called || u.DisplayName != "Framework result" {
		t.Fatal("lookup not delegated")
	}
	called = false
	u, err = d.AuthenticateUser(context.Background(), "alice", "synthetic")
	if err != nil || called || u.DisplayName != "alice" {
		t.Fatal("authentication boundary changed")
	}
	if _, err := d.AuthenticateAdmin(context.Background(), "alice", "synthetic"); err != nil || called {
		t.Fatal("admin policy boundary changed")
	}
}

func TestLookupOverlayPreservesAdministrativePolicyBoundary(t *testing.T) {
	d, err := WithUserLookup(administrativeTestDirectory{}, func(_ context.Context, name string) (*User, error) {
		return &User{Username: name}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	administrative, ok := d.(AdministrativeDirectory)
	if !ok {
		t.Fatal("framework lookup overlay hid administrative role resolver")
	}
	roles, err := administrative.AdministrativeRoles(context.Background(), "alice")
	if err != nil || len(roles) != 1 || roles[0] != adminauth.RoleAuditor {
		t.Fatalf("role resolution was not delegated: %v %v", roles, err)
	}
	user, roles, err := administrative.AuthenticateAdministrative(context.Background(), "alice", "synthetic")
	if err != nil || user.Username != "alice" || len(roles) != 1 || roles[0] != adminauth.RoleAuditor {
		t.Fatalf("administrative authentication was not delegated: %+v %v %v", user, roles, err)
	}
}

func TestLookupOverlayMissingAndUnavailable(t *testing.T) {
	for _, failure := range []error{ErrUserNotFound, context.DeadlineExceeded} {
		d, _ := WithUserLookup(Local{}, func(context.Context, string) (*User, error) { return nil, failure })
		exists, err := d.UserExists(context.Background(), "alice")
		if exists {
			t.Fatal("failed lookup reported existing user")
		}
		if failure == ErrUserNotFound && err != nil {
			t.Fatal(err)
		}
		if failure != ErrUserNotFound && !errors.Is(err, failure) {
			t.Fatal("infrastructure error swallowed")
		}
	}
	if _, err := WithUserLookup(nil, nil); err == nil {
		t.Fatal("missing dependencies accepted")
	}
	d, _ := WithUserLookup(Local{}, func(context.Context, string) (*User, error) { return nil, nil })
	if _, err := d.GetUser(context.Background(), "alice"); err == nil {
		t.Fatal("invalid response accepted")
	}
}
