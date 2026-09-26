package oidc

import (
	"context"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

// providerStore bounds the provider's database dependency for backend contract
// tests. New still accepts the existing SQLite Store; there is no runtime
// PostgreSQL switch. Legacy Audit policy is intentionally unchanged here.
type providerStore interface {
	OIDCClientByID(context.Context, string) (database.OIDCClient, error)
	UserByUsername(context.Context, string) (database.User, error)
	CreateUser(context.Context, string, string, string) (database.User, error)
	GetUser(context.Context, int64) (database.User, error)
	EnsureOIDCSubject(context.Context, int64) (string, error)
	CreateOIDCCode(context.Context, database.OIDCCode) error
	ConsumeOIDCCode(context.Context, string, string, string, time.Time) (database.OIDCCode, error)
	WriteAudit(context.Context, database.Audit) error
}

var _ providerStore = (*database.Store)(nil)
var _ providerStore = (*database.PostgresStore)(nil)
