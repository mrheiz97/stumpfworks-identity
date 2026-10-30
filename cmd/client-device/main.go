package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/TheRealHZL/stumpfworks-identity/internal/deviceclient"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
)

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "client device:", err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println("sw-badge-client-device", version.Version)
		return nil
	}
	if len(args) == 0 || (args[0] != "enroll" && args[0] != "renew") {
		return errors.New("action required: enroll or renew")
	}
	action := args[0]
	flags := flag.NewFlagSet("sw-badge-client-device", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	server := flags.String("server", env("SWBADGE_CLIENT_API_SERVER", ""), "Identity enrollment or mTLS API HTTPS URL")
	activationServer := flags.String("activation-server", env("SWBADGE_CLIENT_API_SERVER", ""), "Identity mTLS API HTTPS URL used after enrollment")
	clientID := flags.String("client-id", env("SWBADGE_CLIENT_ID", ""), "registered client ID")
	serverCA := flags.String("server-ca-file", env("SWBADGE_CA_FILE", ""), "LOGIN01 server CA PEM")
	tokenFile := flags.String("enrollment-token-file", env("SWBADGE_CLIENT_ENROLLMENT_TOKEN_FILE", "/etc/stumpfworks-badge/client-enrollment-token"), "root-readable one-time enrollment token")
	bundleFile := flags.String("bundle-file", env("SWBADGE_DEVICE_BUNDLE_FILE", "/etc/stumpfworks-badge/device-credential.pem"), "root-readable certificate and private-key bundle")
	deviceCAFile := flags.String("device-ca-file", env("SWBADGE_DEVICE_CA_FILE", "/etc/stumpfworks-badge/device-ca.pem"), "public device CA PEM")
	if err := flags.Parse(args[1:]); err != nil {
		return errors.New("invalid arguments")
	}
	if len(flags.Args()) != 0 || *server == "" || *clientID == "" || (action == "enroll" && *activationServer == "") {
		return errors.New("server and client ID are required")
	}
	ctx := context.Background()
	var material deviceclient.Material
	var err error
	if action == "enroll" {
		tokenBytes, readErr := os.ReadFile(*tokenFile)
		if readErr != nil {
			return errors.New("enrollment token could not be read")
		}
		token := strings.TrimSpace(string(tokenBytes))
		client, clientErr := deviceclient.HTTPClient(*serverCA, "", "")
		if clientErr != nil {
			return clientErr
		}
		material, err = deviceclient.Enroll(ctx, client, *server, *clientID, token)
	} else {
		deviceCA, readErr := os.ReadFile(*deviceCAFile)
		if readErr != nil {
			return errors.New("pinned device CA could not be read")
		}
		client, clientErr := deviceclient.HTTPClient(*serverCA, *bundleFile, *bundleFile)
		if clientErr != nil {
			return clientErr
		}
		material, err = deviceclient.Renew(ctx, client, *server, *clientID, deviceCA)
	}
	if err != nil {
		return err
	}
	if err = deviceclient.WriteBundle(*bundleFile, *deviceCAFile, material, action == "renew"); err != nil {
		return errors.New("device credential could not be installed")
	}
	activeServer := *server
	if action == "enroll" {
		activeServer = *activationServer
	}
	activationClient, activationErr := deviceclient.HTTPClient(*serverCA, *bundleFile, *bundleFile)
	if activationErr == nil {
		activationErr = deviceclient.Activate(ctx, activationClient, activeServer)
	}
	if activationErr != nil {
		if rollbackErr := deviceclient.RollbackBundle(*bundleFile, *deviceCAFile, action == "enroll"); rollbackErr != nil {
			return fmt.Errorf("device activation failed and local rollback failed: %w", rollbackErr)
		}
		return errors.New("device activation failed; local credential was rolled back")
	}
	fmt.Printf("client_id=%s\nexpires_at=%s\naction=%s\n", *clientID, material.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"), action)
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
