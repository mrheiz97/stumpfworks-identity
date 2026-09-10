package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/TheRealHZL/stumpfworks-identity/internal/config"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"golang.org/x/crypto/bcrypt"
)

type values []string

func (v *values) String() string     { return strings.Join(*v, ",") }
func (v *values) Set(s string) error { *v = append(*v, s); return nil }

func main() {
	global := flag.NewFlagSet("identity-admin", flag.ExitOnError)
	configPath := global.String("config", "", "Identity configuration file")
	_ = global.Parse(os.Args[1:])
	args := global.Args()
	if len(args) == 0 {
		fail("command required: oidc-client or oidc-subject")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fail("configuration: " + err.Error())
	}
	store, err := database.Open(cfg.DatabasePath)
	if err != nil {
		fail("database: " + err.Error())
	}
	defer store.Close()
	switch args[0] {
	case "oidc-client":
		clientCommand(store, args[1:])
	case "oidc-subject":
		subjectCommand(store, args[1:])
	default:
		fail("unknown command")
	}
}
func clientCommand(store *database.Store, args []string) {
	if len(args) == 0 {
		fail("oidc-client action required: create, rotate-secret, enable, or disable")
	}
	action := args[0]
	fs := flag.NewFlagSet("oidc-client "+action, flag.ExitOnError)
	id := fs.String("client-id", "", "exact OIDC client ID")
	scopes := fs.String("scopes", "openid", "space-separated scopes")
	var redirects values
	fs.Var(&redirects, "redirect-uri", "exact HTTPS redirect URI; repeatable")
	_ = fs.Parse(args[1:])
	if !validID(*id) {
		fail("invalid client ID")
	}
	ctx := context.Background()
	switch action {
	case "create":
		if len(redirects) == 0 {
			fail("at least one redirect URI is required")
		}
		for _, r := range redirects {
			if !validRedirect(r) {
				fail("redirect URIs must be exact HTTPS URLs without fragments")
			}
		}
		requested := strings.Fields(*scopes)
		if !slices.Contains(requested, "openid") {
			fail("openid scope is required")
		}
		for _, s := range requested {
			if s != "openid" && s != "profile" && s != "email" {
				fail("unsupported scope: " + s)
			}
		}
		secret := newSecret()
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			fail("secret hashing failed")
		}
		if err = store.CreateOIDCClient(ctx, *id, string(hash), strings.Join(redirects, "\n"), strings.Join(requested, " ")); err != nil {
			fail("client registration failed")
		}
		fmt.Printf("client_id=%s\nclient_secret=%s\nnotice=This secret is shown once. Store it securely.\n", *id, secret)
	case "rotate-secret":
		if _, err := store.OIDCClientByID(ctx, *id); err != nil {
			fail("client not found")
		}
		secret := newSecret()
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			fail("secret hashing failed")
		}
		if err = store.RotateOIDCClientSecret(ctx, *id, string(hash)); err != nil {
			fail("secret rotation failed")
		}
		fmt.Printf("client_id=%s\nclient_secret=%s\nnotice=This secret is shown once. Store it securely.\n", *id, secret)
	case "enable", "disable":
		if err := store.SetOIDCClientEnabled(ctx, *id, action == "enable"); err != nil {
			fail("client state change failed")
		}
		fmt.Printf("client_id=%s\nenabled=%t\n", *id, action == "enable")
	default:
		fail("unknown oidc-client action")
	}
}
func subjectCommand(store *database.Store, args []string) {
	fs := flag.NewFlagSet("oidc-subject", flag.ExitOnError)
	login := fs.String("login", "", "existing Identity login")
	_ = fs.Parse(args)
	u, err := store.UserByUsername(context.Background(), strings.TrimSpace(*login))
	if err != nil {
		fail("user not found")
	}
	subject, err := store.EnsureOIDCSubject(context.Background(), u.ID)
	if err != nil {
		fail("subject lookup failed")
	}
	fmt.Printf("login=%s\noidc_subject=%s\n", u.Username, subject)
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
func newSecret() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fail("secure random generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
