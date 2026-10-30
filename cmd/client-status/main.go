package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/TheRealHZL/stumpfworks-identity/internal/clientstatus"
	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
)

func value(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	server := flag.String("server", value("SWBADGE_SERVER", ""), "LOGIN01 HTTPS URL")
	clientID := flag.String("client-id", value("SWBADGE_CLIENT_ID", ""), "registered client ID")
	caFile := flag.String("ca-file", value("SWBADGE_CA_FILE", ""), "additional PEM CA certificate")
	tokenFile := flag.String("token-file", value("SWBADGE_CLIENT_TOKEN_FILE", "/etc/stumpfworks-badge/client-status-token"), "root-readable client token file")
	deviceBundleFile := flag.String("device-bundle-file", value("SWBADGE_DEVICE_BUNDLE_FILE", ""), "optional root-readable device certificate and key bundle")
	updateStateFile := flag.String("update-state-file", value("SWBADGE_UPDATE_STATE_FILE", clientupdate.DefaultStatePath), "local updater state file")
	show := flag.Bool("version", false, "show version")
	flag.Parse()
	if *show {
		fmt.Println("sw-badge-client-status", version.Version)
		return
	}
	if *server == "" || *clientID == "" {
		fatal("server and client ID are required")
	}
	token := ""
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			fatal(err.Error())
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" && *deviceBundleFile == "" {
		fatal("client token or device credential is required")
	}
	hc, err := clientstatus.HTTPClientWithCertificate(*caFile, *deviceBundleFile, *deviceBundleFile)
	if err != nil {
		fatal(err.Error())
	}
	report, err := clientstatus.CollectWithUpdateState(context.Background(), *clientID, version.Version, *updateStateFile)
	if err != nil {
		fatal(err.Error())
	}
	if err = clientstatus.Send(context.Background(), hc, *server, token, report); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) { fmt.Fprintln(os.Stderr, "client status:", message); os.Exit(1) }
