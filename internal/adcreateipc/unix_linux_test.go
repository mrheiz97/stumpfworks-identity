//go:build linux

package adcreateipc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func configForTest(t *testing.T) (Config, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("isolated root laboratory required for separate-UID probes")
	}
	dir, e := os.MkdirTemp("/tmp", "identity-create-ipc-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if os.Chown(dir, 0, 65534) != nil || os.Chmod(dir, 0750) != nil {
		t.Fatal("fixture directory")
	}
	return Config{Enabled: true, Socket: filepath.Join(dir, "executor.sock"), Owner: &Identity{UID: 0, GID: 65534}, Peer: &Identity{UID: 65534, GID: 65534}}, dir
}
func TestKernelPeersSeparateProcessAndNoRetry(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-client", "wrong-server", "uncertain", "lost-response", "bad-response", "redirect", "oversize-response", "insecure-socket", "socket-symlink"} {
		t.Run(mode, func(t *testing.T) {
			config, _ := configForTest(t)
			if mode == "wrong-client" {
				config.Peer = &Identity{UID: 65533, GID: 65534}
			}
			backend := &stubOperations{enabled: true}
			if mode == "uncertain" {
				backend.fail = adcreate.ErrUncertain
			}
			server, e := Listen(config, backend)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "insecure-socket" {
				if os.Chmod(config.Socket, 0666) != nil {
					t.Fatal("fixture chmod")
				}
			}
			if mode == "socket-symlink" {
				if os.Rename(config.Socket, config.Socket+".real") != nil || os.Symlink(config.Socket+".real", config.Socket) != nil {
					t.Fatal("fixture link")
				}
			}
			if mode == "lost-response" || mode == "bad-response" || mode == "redirect" || mode == "oversize-response" {
				server.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					backend.calls++
					w.Header().Set("Content-Type", "application/json")
					switch mode {
					case "lost-response":
						conn, _, e := w.(http.Hijacker).Hijack()
						if e == nil {
							conn.Close()
						}
					case "bad-response":
						w.Write([]byte(`{"version":1,"Version":1}`))
					case "redirect":
						w.Header().Set("Location", "http://foreign.invalid/never-follow")
						w.WriteHeader(307)
					case "oversize-response":
						w.Write([]byte(strings.Repeat("x", maxResponse+1)))
					}
				})
			}
			done := make(chan error, 1)
			go func() { done <- server.Serve() }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTransportChild$", "-test.v")
			command.Env = append(os.Environ(), "IDENTITY_CREATE_IPC_CHILD=1", "IDENTITY_CREATE_IPC_SOCKET="+config.Socket, "IDENTITY_CREATE_IPC_MODE="+mode)
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
			output, e := command.CombinedOutput()
			server.Close()
			if serveErr := <-done; serveErr != nil {
				t.Fatal(serveErr)
			}
			if e != nil {
				t.Fatalf("child failed %s", output)
			}
			wanted := 0
			if mode != "wrong-client" && mode != "wrong-server" && mode != "insecure-socket" && mode != "socket-symlink" {
				wanted = 1
			}
			if backend.calls != wanted {
				t.Fatal("unexpected dispatch/retry", backend.calls, wanted)
			}
			if _, e = Listen(config, backend); e == nil {
				t.Fatal("stale endpoint adopted/deleted")
			}
		})
	}
}
func TestTransportChild(t *testing.T) {
	if os.Getenv("IDENTITY_CREATE_IPC_CHILD") != "1" {
		t.Skip("child process only")
	}
	mode := os.Getenv("IDENTITY_CREATE_IPC_MODE")
	gid := uint32(0)
	if mode == "wrong-server" {
		gid = 1
	}
	c, e := NewClient(Config{Enabled: true, Socket: os.Getenv("IDENTITY_CREATE_IPC_SOCKET"), Owner: &Identity{UID: 0, GID: 65534}, Peer: &Identity{UID: 0, GID: gid}})
	if e != nil {
		t.Fatal(e)
	}
	result, e := c.Prepare(context.Background(), "operator", "synthetic-secret", adcreate.Input{Name: "newuser", DisplayName: "New User"})
	if mode == "valid" {
		if e != nil || result.State != "prepared" {
			t.Fatal("valid call", e)
		}
	} else if !errors.Is(e, adcreate.ErrUncertain) {
		t.Fatal("unsafe error mapping", e)
	}
}
func TestSocketPathsAndFencesFailClosed(t *testing.T) {
	for _, mode := range []string{"same-uid", "parent-mode", "parent-link", "socket-file", "socket-link", "lock-link", "lock-hardlink", "lock-mode", "second-listener"} {
		t.Run(mode, func(t *testing.T) {
			c, dir := configForTest(t)
			switch mode {
			case "same-uid":
				c.Peer = &Identity{UID: 0, GID: 0}
			case "parent-mode":
				os.Chmod(dir, 0770)
			case "parent-link":
				link := dir + "-link"
				os.Symlink(dir, link)
				defer os.Remove(link)
				c.Socket = filepath.Join(link, "executor.sock")
			case "socket-file":
				os.WriteFile(c.Socket, []byte("fixture"), 0600)
			case "socket-link":
				os.Symlink("missing", c.Socket)
			case "lock-link":
				os.Symlink("missing", c.Socket+".lock")
			case "lock-hardlink":
				file := filepath.Join(dir, "other")
				os.WriteFile(file, nil, 0600)
				os.Link(file, c.Socket+".lock")
			case "lock-mode":
				os.WriteFile(c.Socket+".lock", nil, 0644)
			case "second-listener":
				server, e := Listen(c, &stubOperations{enabled: true})
				if e != nil {
					t.Fatal(e)
				}
				defer server.Close()
			}
			if server, e := Listen(c, &stubOperations{enabled: true}); e == nil {
				server.Close()
				t.Fatal("unsafe listener accepted")
			}
		})
	}
}
func TestNoSocketOrIdentityDefaults(t *testing.T) {
	c, _ := configForTest(t)
	for _, change := range []func(*Config){func(c *Config) { c.Peer = nil }, func(c *Config) { c.Owner = nil }, func(c *Config) { c.Socket = "relative" }, func(c *Config) { c.Socket += "/../x" }, func(c *Config) { c.Socket = strings.Repeat("a", 200) }} {
		candidate := c
		change(&candidate)
		if _, e := Listen(candidate, &stubOperations{enabled: true}); e == nil {
			t.Fatal("invalid configuration")
		}
	}
	// Configuration copies prevent caller mutation of pins after construction.
	candidate := Config{Enabled: true, Socket: c.Socket, Owner: &Identity{UID: 1, GID: 65534}, Peer: &Identity{UID: 1, GID: 0}}
	client, e := NewClient(candidate)
	if e != nil {
		t.Fatal(e)
	}
	candidate.Peer.GID = 9
	raw, _ := json.Marshal(client.config.Peer)
	if string(raw) != `{"UID":1,"GID":0}` {
		t.Fatal("mutable peer pin")
	}
}
