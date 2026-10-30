package clientstatus

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
)

type Report struct {
	ClientID       string                    `json:"client_id"`
	Version        string                    `json:"version"`
	NetworkStatus  string                    `json:"network_status"`
	ADStatus       string                    `json:"ad_status"`
	CameraStatus   string                    `json:"camera_status"`
	KerberosStatus string                    `json:"kerberos_status"`
	Update         *clientupdate.UpdateState `json:"update,omitempty"`
}

func Collect(ctx context.Context, clientID, version string) Report {
	return Report{ClientID: clientID, Version: version, NetworkStatus: networkStatus(), ADStatus: commandStatus(ctx, "wbinfo", "-t"), CameraStatus: cameraStatus(), KerberosStatus: kerberosStatus()}
}

func CollectWithUpdateState(ctx context.Context, clientID, version, statePath string) (Report, error) {
	report := Collect(ctx, clientID, version)
	state, err := clientupdate.ReadUpdateState(statePath)
	if err != nil {
		return Report{}, err
	}
	report.Update = state
	return report, nil
}

func networkStatus() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	hasUsable := false
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		hasUsable = true
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return "ok"
			}
		}
	}
	if hasUsable {
		return "degraded"
	}
	return "unavailable"
}

func commandStatus(parent context.Context, name string, args ...string) string {
	if _, err := exec.LookPath(name); err != nil {
		return "unavailable"
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "degraded"
	}
	return "ok"
}

func cameraStatus() string {
	devices, err := filepath.Glob("/dev/video*")
	if err != nil {
		return "unknown"
	}
	if len(devices) == 0 {
		return "unavailable"
	}
	return "ok"
}

func kerberosStatus() string {
	if _, err := exec.LookPath("kinit"); err != nil {
		return "unavailable"
	}
	plugins, err := filepath.Glob("/usr/lib/*/krb5/plugins/preauth/pkinit.so")
	if err != nil {
		return "unknown"
	}
	if len(plugins) == 0 {
		return "degraded"
	}
	return "ok"
}

func HTTPClient(caFile string) (*http.Client, error) {
	return HTTPClientWithCertificate(caFile, "", "")
}

func HTTPClientWithCertificate(caFile, certificateFile, keyFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	var tlsConfig *tls.Config
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if certificateFile != "" || keyFile != "" {
		if certificateFile == "" || keyFile == "" {
			return nil, errors.New("both device certificate and key files are required")
		}
		certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
		if err != nil {
			return nil, errors.New("device credential could not be loaded")
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}, nil
}

func Send(ctx context.Context, hc *http.Client, server, token string, report Report) error {
	if !strings.HasPrefix(server, "https://") {
		return errors.New("status reporting requires an HTTPS server URL")
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/api/v1/client/status", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status server returned HTTP %d", resp.StatusCode)
	}
	return nil
}
