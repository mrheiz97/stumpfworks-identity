package adprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreateipc"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type transportLabInput struct {
	Username, Password, Name, ID string
	PrepareOnly, Recovery        bool
}

func runCreateTransportLab(t *testing.T, service *adcreate.Service, password string) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("isolated Linux root fixture required")
	}
	dir, e := os.MkdirTemp("/tmp", "identity-create-transport-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if os.Chown(dir, 0, 65534) != nil || os.Chmod(dir, 0750) != nil {
		t.Fatal("socket directory")
	}
	config := adcreateipc.Config{Enabled: true, Socket: filepath.Join(dir, "executor.sock"), Owner: &adcreateipc.Identity{UID: 0, GID: 65534}, Peer: &adcreateipc.Identity{UID: 65534, GID: 65534}}
	clientSocket := config.Socket
	if os.Getenv("IDENTITY_CREATE_SSH_LAB") == "1" {
		config.Socket = "/tmp/create-ssh-lab/dc/executor.sock"
		config.Owner.GID = 65531
		config.Peer = &adcreateipc.Identity{UID: 65531, GID: 65531}
		clientSocket = "/tmp/create-ssh-lab/login/relay.sock"
		conn, err := net.DialTimeout("unix", clientSocket, time.Second)
		if err != nil {
			t.Fatal("SSH relay socket", err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		var byteBuffer [1]byte
		_, err = conn.Read(byteBuffer[:])
		conn.Close()
		if !errors.Is(err, io.EOF) {
			t.Fatal("relay accepted the wrong local UID", err)
		}
	}
	server, e := adcreateipc.Listen(config, service)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	defer func() {
		server.Close()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	raw, _ := json.Marshal(transportLabInput{Username: "operator", Password: password})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCreateTransportChild$", "-test.v")
	command.Env = append(os.Environ(), "IDENTITY_CREATE_TRANSPORT_CHILD=1", "IDENTITY_CREATE_TRANSPORT_SOCKET="+clientSocket)
	command.Stdin = bytes.NewReader(raw)
	setCreateChildIdentity(command)
	output, e := command.CombinedOutput()
	if e != nil {
		t.Fatalf("separate-UID transport child failed: %s", output)
	}
	t.Log("separate UID web client reached real Create service, journal and native disabled Add")
}
func TestCreateTransportChild(t *testing.T) {
	if os.Getenv("IDENTITY_CREATE_TRANSPORT_CHILD") != "1" {
		t.Skip("separate-UID laboratory subprocess only")
	}
	if os.Geteuid() != 65534 {
		t.Fatal("privilege separation missing")
	}
	dir, config, _ := createFixturePaths()
	for _, path := range []string{dir + "/issuer.pem", dir + "/journal.tdb", dir + "/create-identity.db", config} {
		if _, e := os.ReadFile(path); e == nil {
			t.Fatal("web UID can read private executor/DC files")
		}
	}
	var actor transportLabInput
	if json.NewDecoder(io.LimitReader(os.Stdin, 4096)).Decode(&actor) != nil {
		t.Fatal("actor input")
	}
	owner := &adcreateipc.Identity{UID: 0, GID: 65534}
	peer := &adcreateipc.Identity{UID: 0, GID: 0}
	if os.Getenv("IDENTITY_CREATE_SSH_LAB") == "1" {
		owner.UID, peer.UID, peer.GID = 65532, 65532, 65534
	}
	client, e := adcreateipc.NewClient(adcreateipc.Config{Enabled: true, Socket: os.Getenv("IDENTITY_CREATE_TRANSPORT_SOCKET"), Owner: owner, Peer: peer})
	if e != nil {
		t.Fatal(e)
	}
	if os.Getenv("IDENTITY_CREATE_SSH_LAB") == "1" {
		if _, err := client.Prepare(context.Background(), "profileonly", actor.Password,
			adcreate.Input{Name: "relayblocked", DisplayName: "Relay Role Denied"}); !errors.Is(err, adcreate.ErrDenied) {
			t.Fatal("SSH relay bypassed the executor's Creator role", err)
		}
	}
	if actor.ID != "" {
		status, e := client.Action(context.Background(), actor.Username, actor.Password, actor.ID, "status", "")
		if actor.Recovery && actor.PrepareOnly {
			if e != nil || status.State != "prepared" || status.Plan.Digest == "" {
				t.Fatal("archived prepared plan missing", e)
			}
			for _, action := range []string{"confirm", "cancel"} {
				digest := ""
				if action == "confirm" {
					digest = status.Plan.Digest
				}
				if _, e = client.Action(context.Background(), actor.Username, actor.Password, actor.ID, action, digest); !errors.Is(e, adcreate.ErrDenied) {
					t.Fatal("recovery accepted a mutation", action, e)
				}
			}
			return
		}
		if e != nil || status.State != "succeeded" {
			t.Fatal("persisted status", e)
		}
		evidence, e := client.Action(context.Background(), actor.Username, actor.Password, actor.ID, "evidence", "")
		if e != nil || evidence.Evidence == nil || evidence.Evidence.GUID != status.Result.GUID {
			t.Fatal("persisted receipt", e)
		}
		if actor.Recovery {
			if _, e = client.Prepare(context.Background(), actor.Username, actor.Password, adcreate.Input{Name: "recoverynew", DisplayName: "Recovery User"}); !errors.Is(e, adcreate.ErrDenied) {
				t.Fatal("recovery accepted a new plan", e)
			}
		}
		return
	}
	if actor.Name == "" {
		actor.Name = "transportuser"
	}
	plan, e := client.Prepare(context.Background(), actor.Username, actor.Password, adcreate.Input{Name: actor.Name, DisplayName: "Transport User"})
	if e != nil || plan.State != "prepared" {
		t.Fatal("transport prepare", e)
	}
	if actor.PrepareOnly {
		return
	}
	result, e := client.Action(context.Background(), actor.Username, actor.Password, plan.Plan.ID, "confirm", plan.Plan.Digest)
	if e != nil || result.State != "succeeded" || result.Result.GUID == "" {
		t.Fatal("transport confirm", e)
	}
	_, e = client.Action(context.Background(), actor.Username, actor.Password, plan.Plan.ID, "confirm", plan.Plan.Digest)
	if !errors.Is(e, adcreate.ErrDenied) {
		t.Fatal("transport duplicate replay")
	}
	events, e := client.History(context.Background(), actor.Username, actor.Password, plan.Plan.ID)
	if e != nil || len(events) < 4 {
		t.Fatal("transport audit")
	}
}
