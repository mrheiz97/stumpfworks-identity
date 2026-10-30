package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/config"
)

func clientAPIServer(cfg config.Config, application http.Handler) (*http.Server, error) {
	if !cfg.ClientAPIEnabled {
		return nil, nil
	}
	if application == nil || strings.TrimSpace(cfg.ClientAPIListen) == "" || cfg.ClientAPIListen == cfg.Listen || cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.ClientAPICAFile == "" {
		return nil, errors.New("client API requires a distinct listener, server TLS certificate and device CA")
	}
	caPEM, err := os.ReadFile(cfg.ClientAPICAFile)
	if err != nil {
		return nil, fmt.Errorf("read client API CA: %w", err)
	}
	if len(caPEM) == 0 || len(caPEM) > 1<<20 {
		return nil, errors.New("client API CA must contain at most 1 MiB")
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("client API CA contains no certificates")
	}
	restricted := http.NewServeMux()
	restricted.Handle("POST /api/v1/client/status", application)
	return &http.Server{
		Addr:              cfg.ClientAPIListen,
		Handler:           restricted,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
		},
	}, nil
}
