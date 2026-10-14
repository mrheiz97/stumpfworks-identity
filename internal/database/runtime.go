package database

import (
	"context"
	"time"
)

// ApplicationStore is the database boundary used by the Identity HTTP server.
// Backend lifecycle, migrations and imports stay outside this interface so the
// runtime user never gains schema privileges implicitly.
type ApplicationStore interface {
	CreateUser(context.Context, string, string, string) (User, error)
	CreateUserWithAudit(context.Context, string, string, string, string, string) (User, error)
	GetUser(context.Context, int64) (User, error)
	UserByUsername(context.Context, string) (User, error)
	Users(context.Context) ([]User, error)
	SetUserPIN(context.Context, int64, string) error
	SetUserPINWithAudit(context.Context, int64, string, string, string) error
	CreateBadge(context.Context, int64, string, string) (Badge, error)
	CreateBadgeWithAudit(context.Context, int64, string, string, string) (Badge, error)
	ReplaceBadgePending(context.Context, int64, string, string) (Badge, error)
	ReplaceBadgePendingWithAudit(context.Context, int64, string, string, string) (Badge, error)
	GetBadge(context.Context, int64) (Badge, error)
	BadgeByCode(context.Context, string) (Badge, error)
	Badges(context.Context) ([]Badge, error)
	ActiveBadgesByUser(context.Context, int64) ([]UserBadge, error)
	RevokeActiveBadgeForUser(context.Context, int64, int64) (UserBadge, error)
	RevokeActiveBadgeForUserWithAudit(context.Context, int64, int64, string) (UserBadge, error)
	ActivatePendingBadgeForUser(context.Context, int64, int64) error
	ActivatePendingBadgeForUserWithAudit(context.Context, int64, int64, string) error
	Revoke(context.Context, int64) error
	RevokeBadgeWithAudit(context.Context, int64, string) error
	Used(context.Context, int64) error
	RecordBadgeAuthenticationSuccess(context.Context, int64, string, string) error
	WriteAudit(context.Context, Audit) error
	Audits(context.Context) ([]Audit, error)
	RecentBadgeAuthByUser(context.Context, string) ([]UserAuthEvent, error)
	CreateSelfServiceSession(context.Context, string, string, time.Time) error
	CreateSelfServiceSessionWithAudit(context.Context, string, string, time.Time, string) error
	ActiveSelfServiceSession(context.Context, string, string, time.Time) (SelfServiceSession, error)
	ActiveSelfServiceSessions(context.Context, string, time.Time) ([]SelfServiceSession, error)
	RevokeOtherSelfServiceSessions(context.Context, string, string) (int64, error)
	RevokeOtherSelfServiceSessionsWithAudit(context.Context, string, string, string) (int64, error)
	RevokeSelfServiceSession(context.Context, string, string) error
	Counts(context.Context) (map[string]int64, error)
	ClientByID(context.Context, string) (Client, error)
	Clients(context.Context) ([]Client, error)
	UpdateClientStatusWithUpdate(context.Context, string, string, string, string, string, string, *ClientUpdate) error
	CreateClient(context.Context, string, string) (Client, error)
	CreateClientWithAudit(context.Context, string, string, string) (Client, error)
	RotateClientToken(context.Context, string, string) error
	RotateClientTokenWithAudit(context.Context, string, string, string) error
	SetClientEnabled(context.Context, string, bool) error
	SetClientEnabledWithAudit(context.Context, string, bool, string) error
	EnsureOIDCSubject(context.Context, int64) (string, error)
	EnsureOIDCSubjectWithAudit(context.Context, int64, string) (string, error)
	OIDCClientByID(context.Context, string) (OIDCClient, error)
	OIDCClients(context.Context) ([]OIDCClient, error)
	CreateOIDCClientWithAudit(context.Context, string, string, string, string, string) error
	RotateOIDCClientSecretWithAudit(context.Context, string, string, string) error
	SetOIDCClientEnabledWithAudit(context.Context, string, bool, string) error
	CreateOIDCCode(context.Context, OIDCCode) error
	ConsumeOIDCCode(context.Context, string, string, string, time.Time) (OIDCCode, error)
	CreateOIDCCodeWithAudit(context.Context, OIDCCode, string, string) error
	OIDCCodeForExchange(context.Context, string, string, string, time.Time) (OIDCCode, error)
	ConsumeOIDCCodeWithAudit(context.Context, string, string, string, time.Time, string) (OIDCCode, error)
}

var _ ApplicationStore = (*Store)(nil)
var _ ApplicationStore = (*PostgresStore)(nil)
