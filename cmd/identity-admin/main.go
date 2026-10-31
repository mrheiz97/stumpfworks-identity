package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/config"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"golang.org/x/crypto/bcrypt"
)

type identityAdminStore interface {
	OIDCClientByID(context.Context, string) (database.OIDCClient, error)
	CreateOIDCClientWithAudit(context.Context, string, string, string, string, string) error
	RotateOIDCClientSecretWithAudit(context.Context, string, string, string) error
	SetOIDCClientEnabledWithAudit(context.Context, string, bool, string) error
	UserByUsername(context.Context, string) (database.User, error)
	EnsureOIDCSubjectWithAudit(context.Context, int64, string) (string, error)
	CreateEmergencyAdminGrantWithAudit(context.Context, database.EmergencyAdminGrant, string) error
	EmergencyAdminGrants(context.Context, time.Time) ([]database.EmergencyAdminGrant, error)
	RevokeEmergencyAdminGrantWithAudit(context.Context, string, string) error
	CreateClientEnrollmentTokenWithAudit(context.Context, database.ClientEnrollmentToken, string) error
}

type values []string

func (v *values) String() string     { return strings.Join(*v, ",") }
func (v *values) Set(s string) error { *v = append(*v, s); return nil }

func main() {
	if err := execute(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute(args []string, output io.Writer) error {
	global := flag.NewFlagSet("identity-admin", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	configPath := global.String("config", "", "Identity configuration file")
	if err := global.Parse(args); err != nil {
		return errors.New("invalid command arguments")
	}
	args = global.Args()
	if len(args) == 0 {
		return errors.New("command required: oidc-client, oidc-subject, emergency-admin, or client-enrollment")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return errors.New("configuration could not be loaded")
	}
	store, closeStore, err := database.OpenRuntime(context.Background(), database.RuntimeOptions{
		Backend: cfg.DatabaseBackend, SQLitePath: cfg.DatabasePath,
		PostgreSQLURL: cfg.DatabaseURL, PostgreSQLAllowInsecure: cfg.DatabaseAllowInsecure,
	})
	if err != nil {
		return errors.New("database could not be opened")
	}
	defer closeStore()
	switch args[0] {
	case "oidc-client":
		return clientCommand(context.Background(), store, args[1:], output)
	case "oidc-subject":
		return subjectCommand(context.Background(), store, args[1:], output)
	case "emergency-admin":
		if !cfg.EmergencyAdminEnabled {
			return errors.New("emergency administrator access is disabled")
		}
		return emergencyAdminCommand(context.Background(), store, args[1:], output)
	case "client-enrollment":
		return clientEnrollmentCommand(context.Background(), store, args[1:], output)
	default:
		return errors.New("unknown command")
	}
}

func clientEnrollmentCommand(ctx context.Context, store identityAdminStore, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "issue" {
		return errors.New("client-enrollment action required: issue")
	}
	fs := flag.NewFlagSet("client-enrollment issue", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	clientID := fs.String("client-id", "", "registered managed-client ID")
	minutes := fs.Int("minutes", 10, "lifetime in minutes (5-60)")
	if err := fs.Parse(args[1:]); err != nil {
		return errors.New("invalid client-enrollment arguments")
	}
	if !validID(*clientID) || len(*clientID) > 64 || *minutes < 5 || *minutes > 60 {
		return errors.New("valid client ID and lifetime between 5 and 60 minutes required")
	}
	id, err := newSecret()
	if err != nil {
		return errors.New("secure random generation failed")
	}
	token, err := newSecret()
	if err != nil {
		return errors.New("secure random generation failed")
	}
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	enrollment := database.ClientEnrollmentToken{ID: id, ClientID: *clientID, TokenHash: hex.EncodeToString(hash[:]), CreatedAt: now, ExpiresAt: now.Add(time.Duration(*minutes) * time.Minute)}
	if err = store.CreateClientEnrollmentTokenWithAudit(ctx, enrollment, ""); err != nil {
		return errors.New("client enrollment token creation failed")
	}
	fmt.Fprintf(output, "enrollment_id=%s\nclient_id=%s\nenrollment_token=%s\nexpires_at=%s\nnotice=This token is shown once and can be used only once.\n", enrollment.ID, enrollment.ClientID, token, enrollment.ExpiresAt.Format(time.RFC3339))
	return nil
}

func emergencyAdminCommand(ctx context.Context, store identityAdminStore, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("emergency-admin action required: issue, list, or revoke")
	}
	action := args[0]
	fs := flag.NewFlagSet("emergency-admin "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	minutes := fs.Int("minutes", 15, "lifetime in minutes (5-60)")
	id := fs.String("id", "", "emergency grant ID")
	if err := fs.Parse(args[1:]); err != nil {
		return errors.New("invalid emergency-admin arguments")
	}
	switch action {
	case "issue":
		if *minutes < 5 || *minutes > 60 {
			return errors.New("emergency lifetime must be between 5 and 60 minutes")
		}
		grantID, err := newSecret()
		if err != nil {
			return errors.New("secure random generation failed")
		}
		token, err := newSecret()
		if err != nil {
			return errors.New("secure random generation failed")
		}
		sum := sha256.Sum256([]byte(token))
		now := time.Now().UTC()
		grant := database.EmergencyAdminGrant{ID: grantID, TokenHash: hex.EncodeToString(sum[:]), CreatedAt: now, ExpiresAt: now.Add(time.Duration(*minutes) * time.Minute)}
		if err = store.CreateEmergencyAdminGrantWithAudit(ctx, grant, ""); err != nil {
			return errors.New("emergency grant creation failed")
		}
		fmt.Fprintf(output, "grant_id=%s\nemergency_token=%s\nexpires_at=%s\nnotice=This token is shown once and can be used only once.\n", grant.ID, token, grant.ExpiresAt.Format(time.RFC3339))
	case "list":
		grants, err := store.EmergencyAdminGrants(ctx, time.Now().UTC())
		if err != nil {
			return errors.New("emergency grants could not be listed")
		}
		for _, grant := range grants {
			status := "unused"
			if grant.RevokedAt.Valid {
				status = "revoked"
			} else if grant.ConsumedAt.Valid {
				status = "active"
			}
			fmt.Fprintf(output, "grant_id=%s status=%s expires_at=%s\n", grant.ID, status, grant.ExpiresAt.UTC().Format(time.RFC3339))
		}
	case "revoke":
		if strings.TrimSpace(*id) == "" || len(*id) > 128 {
			return errors.New("valid emergency grant ID required")
		}
		if err := store.RevokeEmergencyAdminGrantWithAudit(ctx, *id, ""); err != nil {
			return errors.New("emergency grant revocation failed")
		}
		fmt.Fprintf(output, "grant_id=%s\nrevoked=true\n", *id)
	default:
		return errors.New("unknown emergency-admin action")
	}
	return nil
}

func clientCommand(ctx context.Context, store identityAdminStore, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("oidc-client action required: create, rotate-secret, enable, or disable")
	}
	action := args[0]
	fs := flag.NewFlagSet("oidc-client "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("client-id", "", "exact OIDC client ID")
	scopes := fs.String("scopes", "openid", "space-separated scopes")
	var redirects values
	fs.Var(&redirects, "redirect-uri", "exact HTTPS redirect URI; repeatable")
	if err := fs.Parse(args[1:]); err != nil {
		return errors.New("invalid oidc-client arguments")
	}
	if !validID(*id) {
		return errors.New("invalid client ID")
	}
	switch action {
	case "create":
		if len(redirects) == 0 {
			return errors.New("at least one redirect URI is required")
		}
		for _, r := range redirects {
			if !validRedirect(r) {
				return errors.New("redirect URIs must be exact HTTPS URLs without fragments")
			}
		}
		requested := strings.Fields(*scopes)
		if !slices.Contains(requested, "openid") {
			return errors.New("openid scope is required")
		}
		for _, s := range requested {
			if s != "openid" && s != "profile" && s != "email" {
				return errors.New("unsupported scope")
			}
		}
		secret, err := newSecret()
		if err != nil {
			return errors.New("secure random generation failed")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return errors.New("secret hashing failed")
		}
		if err = store.CreateOIDCClientWithAudit(ctx, *id, string(hash), strings.Join(redirects, "\n"), strings.Join(requested, " "), ""); err != nil {
			return errors.New("client registration failed")
		}
		fmt.Fprintf(output, "client_id=%s\nclient_secret=%s\nnotice=This secret is shown once. Store it securely.\n", *id, secret)
	case "rotate-secret":
		if _, err := store.OIDCClientByID(ctx, *id); err != nil {
			return errors.New("client not found")
		}
		secret, err := newSecret()
		if err != nil {
			return errors.New("secure random generation failed")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return errors.New("secret hashing failed")
		}
		if err = store.RotateOIDCClientSecretWithAudit(ctx, *id, string(hash), ""); err != nil {
			return errors.New("secret rotation failed")
		}
		fmt.Fprintf(output, "client_id=%s\nclient_secret=%s\nnotice=This secret is shown once. Store it securely.\n", *id, secret)
	case "enable", "disable":
		if err := store.SetOIDCClientEnabledWithAudit(ctx, *id, action == "enable", ""); err != nil {
			return errors.New("client state change failed")
		}
		fmt.Fprintf(output, "client_id=%s\nenabled=%t\n", *id, action == "enable")
	default:
		return errors.New("unknown oidc-client action")
	}
	return nil
}
func subjectCommand(ctx context.Context, store identityAdminStore, args []string, output io.Writer) error {
	fs := flag.NewFlagSet("oidc-subject", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	login := fs.String("login", "", "existing Identity login")
	if err := fs.Parse(args); err != nil {
		return errors.New("invalid oidc-subject arguments")
	}
	u, err := store.UserByUsername(ctx, strings.TrimSpace(*login))
	if err != nil {
		return errors.New("user not found")
	}
	subject, err := store.EnsureOIDCSubjectWithAudit(ctx, u.ID, "")
	if err != nil {
		return errors.New("subject lookup failed")
	}
	fmt.Fprintf(output, "login=%s\noidc_subject=%s\n", u.Username, subject)
	return nil
}
func validID(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func validRedirect(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Fragment == "" && u.User == nil
}
func newSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
