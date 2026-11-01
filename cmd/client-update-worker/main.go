package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/deviceclient"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
)

func main() {
	server := flag.String("server", os.Getenv("SWBADGE_DEVICE_SERVER"), "device API HTTPS origin")
	client := flag.String("client-id", os.Getenv("SWBADGE_CLIENT_ID"), "registered client ID")
	ca := flag.String("ca-file", os.Getenv("SWBADGE_CA_FILE"), "server TLS CA")
	bundle := flag.String("device-bundle-file", os.Getenv("SWBADGE_DEVICE_BUNDLE_FILE"), "device credential bundle")
	key := flag.String("public-key", "/etc/stumpfworks-badge/client-update.pub", "trusted stable release public key")
	show := flag.Bool("version", false, "show version")
	flag.Parse()
	if *show {
		fmt.Println("sw-badge-client-update-worker", version.Version)
		return
	}
	if *bundle == "" {
		fmt.Fprintln(os.Stderr, "update worker: device credential required")
		os.Exit(1)
	}
	hc, e := deviceclient.HTTPClient(*ca, *bundle, *bundle)
	if e == nil {
		e = clientupdate.RunWorker(context.Background(), clientupdate.WorkerOptions{Server: *server, ClientID: *client, HTTP: hc, PublicKeyFile: *key, Directory: "/var/lib/stumpfworks-badge/update-jobs"})
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "update worker: operation failed; retry or inspect bounded job state")
		os.Exit(1)
	}
}
