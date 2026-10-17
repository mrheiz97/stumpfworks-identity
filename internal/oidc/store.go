package oidc

import (
	"context"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

// providerStore bounds the provider's database dependency for backend contract
// tests. Both runtime backends implement the same fail-closed issuance paths.
type providerStore interface {
	OIDCClientByID(context.Context, string) (database.OIDCClient, error)
	UserByUsername(context.Context, string) (database.User, error)
	CreateUserWithAudit(context.Context, string, string, string, string, string) (database.User, error)
	GetUser(context.Context, int64) (database.User, error)
	EnsureOIDCSubjectWithAudit(context.Context, int64, string) (string, error)
	ConsumeOIDCCode(context.Context, string, string, string, time.Time) (database.OIDCCode, error)
	CreateOIDCCodeWithAudit(context.Context, database.OIDCCode, string, string) error
	OIDCCodeForExchange(context.Context, string, string, string, time.Time) (database.OIDCCode, error)
	ConsumeOIDCCodeWithAudit(context.Context, string, string, string, time.Time, string) (database.OIDCCode, error)
	ConsumeOIDCCodeWithSessionAudit(context.Context, string, string, string, time.Time, database.OIDCSession, string) (database.OIDCCode, error)
	OIDCSessionByTokenHash(context.Context, string, string, time.Time) (database.OIDCSession, error)
	RevokeOIDCSessionByTokenHashWithAudit(context.Context, string, string, string) error
	WriteAudit(context.Context, database.Audit) error
}

var _ providerStore = (*database.Store)(nil)
var _ providerStore = (*database.PostgresStore)(nil)
