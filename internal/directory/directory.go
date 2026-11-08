package directory

import (
	"context"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
)

type User struct{ Username, DisplayName, DN, Mail string }
type Directory interface {
	UserExists(context.Context, string) (bool, error)
	GetUser(context.Context, string) (*User, error)
	ListUsers(context.Context) ([]User, error)
	AuthenticateUser(context.Context, string, string) (*User, error)
	AuthenticateAdmin(context.Context, string, string) (*User, error)
}

// AdministrativeDirectory resolves current administrative roles separately
// from the legacy full-administrator authentication boundary.
type AdministrativeDirectory interface {
	Directory
	AdministrativeRoles(context.Context, string) ([]adminauth.Role, error)
	AuthenticateAdministrative(context.Context, string, string) (*User, []adminauth.Role, error)
}

// UserCreationSessionDirectory explicitly attests the stricter AD/TLS/group-pin
// prerequisites. Legacy/local adapters never receive a compatibility fallback.
type UserCreationSessionDirectory interface {
	AdministrativeDirectory
	UserCreationSessionsAllowed() bool
}
type Local struct{}

func (Local) UserExists(context.Context, string) (bool, error) { return true, nil }
func (Local) GetUser(_ context.Context, u string) (*User, error) {
	return &User{Username: u, DisplayName: u}, nil
}
func (Local) ListUsers(context.Context) ([]User, error) { return nil, nil }
func (Local) AuthenticateUser(_ context.Context, u, _ string) (*User, error) {
	return &User{Username: u, DisplayName: u}, nil
}
func (Local) AuthenticateAdmin(_ context.Context, u, _ string) (*User, error) {
	return &User{Username: u, DisplayName: u}, nil
}
