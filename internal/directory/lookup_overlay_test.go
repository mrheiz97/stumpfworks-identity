package directory

import (
	"context"
	"errors"
	"testing"
)

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
