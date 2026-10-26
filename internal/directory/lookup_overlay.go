package directory

import (
	"context"
	"errors"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
)

// UserLookup is consumer-owned so the framework adapter can project results
// without exposing framework types to Identity's server or auth policy.
type UserLookup func(context.Context, string) (*User, error)

type lookupOverlay struct {
	Directory
	lookup UserLookup
}

func (d *lookupOverlay) AdministrativeRoles(ctx context.Context, username string) ([]adminauth.Role, error) {
	administrative, ok := d.Directory.(AdministrativeDirectory)
	if !ok {
		return nil, ErrNotAuthorized
	}
	return administrative.AdministrativeRoles(ctx, username)
}

func (d *lookupOverlay) AuthenticateAdministrative(ctx context.Context, username, password string) (*User, []adminauth.Role, error) {
	administrative, ok := d.Directory.(AdministrativeDirectory)
	if !ok {
		return nil, nil, ErrNotAuthorized
	}
	return administrative.AuthenticateAdministrative(ctx, username, password)
}

// WithUserLookup replaces only read-only single-user lookups. Listing and
// authentication remain with the existing implementation. It is not enabled
// in the production startup path until a framework bridge passes acceptance.
func WithUserLookup(existing Directory, lookup UserLookup) (Directory, error) {
	if existing == nil || lookup == nil {
		return nil, errors.New("directory lookup overlay requires both adapters")
	}
	return &lookupOverlay{Directory: existing, lookup: lookup}, nil
}

func (d *lookupOverlay) GetUser(ctx context.Context, username string) (*User, error) {
	u, err := d.lookup(ctx, username)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Username == "" {
		return nil, errors.New("directory lookup returned invalid user")
	}
	return u, nil
}

func (d *lookupOverlay) UserExists(ctx context.Context, username string) (bool, error) {
	_, err := d.GetUser(ctx, username)
	if errors.Is(err, ErrUserNotFound) {
		return false, nil
	}
	return err == nil, err
}
