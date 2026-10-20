package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"

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
		return errors.New("command required: oidc-client or oidc-subject")
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
	default:
		return errors.New("unknown command")
	}
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
