//go:build linux

package adprofile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreateipc"
)

func TestCreateExecutorProcess(t *testing.T) {
	if os.Getenv("IDENTITY_NATIVE_CREATE_LAB") != "1" {
		t.Skip("isolated Create fixture required")
	}
	dir, fixturePath, epoch := createFixturePaths()
	binary := "/workspace/dist/ad-profile-tests/create-executor"
	if epoch != 0 {
		binary = "/tests/create-executor"
	}
	if os.Getenv("IDENTITY_TEST_INSTALLED_CREATE") == "1" {
		binary = "/opt/stumpfworks-badge/create-executor"
		if _, err := os.Stat("/etc/stumpfworks-badge/ad-create.enabled"); !os.IsNotExist(err) {
			t.Fatal("package unexpectedly provisioned activation marker")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	state := t.TempDir()
	socketDir, e := os.MkdirTemp("/tmp", "create-executor-socket-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(socketDir)
	if os.Chown(socketDir, 0, 65534) != nil || os.Chmod(socketDir, 0750) != nil {
		t.Fatal("socket directory")
	}
	socket := filepath.Join(socketDir, "create.sock")
	invoke := func(ok bool, args ...string) {
		t.Helper()
		output, e := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if (e == nil) != ok {
			t.Fatalf("unexpected executor result: %v %s", e, output)
		}
	}
	invoke(true, "-state", "/unavailable")
	invoke(false, "-state", state, "-enable")
	read := func(path string) []byte {
		t.Helper()
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		return data
	}
	write := func(name string, data []byte) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(state, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	var fixture struct{ Config Config }
	var pins nativePins
	if json.Unmarshal(read(fixturePath), &fixture) != nil || json.Unmarshal(read(dir+"/pins.json"), &pins) != nil {
		t.Fatal("fixture")
	}
	key := make([]byte, 32)
	if _, e = rand.Read(key); e != nil {
		t.Fatal(e)
	}
	write("journal.key", key)
	write("issuer.pem", read(dir+"/issuer.pem"))
	password := read(fixture.Config.PasswordFile)
	write("writer.password", password)
	write("ca.pem", read(fixture.Config.CAFile))
	cfg := struct {
		Directory Config
		Pins      CreatePins
		OU        string
		Transport adcreateipc.Config
	}{fixture.Config, CreatePins{ActorGUID: pins.ActorGUID, ActorSID: pins.ActorSID, WriterGUID: pins.WriterGUID, ReceiptPublic: pins.ReceiptPublic, Scope: pins.Scope, Epoch: epoch}, string(read(dir + "/create-ou")),
		adcreateipc.Config{Enabled: true, Socket: socket, Owner: &adcreateipc.Identity{UID: 0, GID: 65534}, Peer: &adcreateipc.Identity{UID: 65534, GID: 65534}}}
	save := func() {
		raw, e := json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		write("config.json", raw)
	}
	save()
	invoke(true, "-state", state, "-initialize-journal")
	invoke(false, "-state", state, "-initialize-journal")
	if epoch != 0 {
		cfg.Pins.Epoch++
		save()
		invoke(false, "-state", state, "-enable")
		cfg.Pins.Epoch = epoch
		save()
	}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	write("journal.key", wrong)
	invoke(false, "-state", state, "-enable")
	write("journal.key", key)
	write("writer.password", []byte("invalid laboratory credential"))
	invoke(false, "-state", state, "-enable")
	write("writer.password", password)
	issuer := read(dir + "/issuer.pem")
	_, different, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(different)
	if e != nil {
		t.Fatal(e)
	}
	write("issuer.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	invoke(false, "-state", state, "-enable")
	if _, e = os.Lstat(socket); !os.IsNotExist(e) {
		t.Fatal("socket opened before signed probe")
	}
	write("issuer.pem", issuer)
	if e = os.Chmod(filepath.Join(state, "issuer.pem"), 0640); e != nil {
		t.Fatal(e)
	}
	invoke(false, "-state", state, "-enable")
	if e = os.Chmod(filepath.Join(state, "issuer.pem"), 0600); e != nil {
		t.Fatal(e)
	}
	start := func() func() {
		process := exec.CommandContext(ctx, binary, "-state", state, "-enable")
		var output bytes.Buffer
		process.Stderr = &output
		if e = process.Start(); e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		finished := false
		t.Cleanup(func() {
			if !finished {
				process.Process.Kill()
				<-done
			}
		})
		for {
			if _, e = os.Lstat(socket); e == nil {
				break
			}
			select {
			case e = <-done:
				finished = true
				t.Fatalf("executor stopped: %v %s", e, output.String())
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		return func() {
			if e = process.Process.Signal(syscall.SIGTERM); e != nil {
				t.Fatal(e)
			}
			e = <-done
			finished = true
			if e != nil {
				t.Fatalf("executor shutdown: %v %s", e, output.String())
			}
			if _, e = os.Lstat(socket); e != nil {
				t.Fatal("socket unexpectedly removed")
			}
		}
	}
	runClient := func(actor transportLabInput) {
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCreateTransportChild$")
		child.Env = append(os.Environ(), "IDENTITY_CREATE_TRANSPORT_CHILD=1", "IDENTITY_CREATE_TRANSPORT_SOCKET="+socket)
		actor.Username = "operator"
		actor.Password = strings.TrimRight(string(password), "\r\n")
		raw, _ := json.Marshal(actor)
		child.Stdin = bytes.NewReader(raw)
		setCreateChildIdentity(child)
		if out, e := child.CombinedOutput(); e != nil {
			t.Fatalf("executor client: %v %s", e, out)
		}
	}
	stop := start()
	previousSocket := socket
	socket = filepath.Join(socketDir, "restart.sock")
	cfg.Transport.Socket = socket
	save()
	invoke(false, "-state", state, "-enable")
	socket = previousSocket
	archiveDir := t.TempDir()
	archive := filepath.Join(archiveDir, "create.backup")
	invoke(false, "-state", state, "-backup-journal", archive)
	runClient(transportLabInput{Name: "executoruser"})
	runClient(transportLabInput{Name: "archiveplan", PrepareOnly: true})
	stop()
	db, e := sql.Open("sqlite", "file:"+filepath.Join(state, "journal.db")+"?mode=ro")
	if e != nil {
		t.Fatal(e)
	}
	var id, prepared string
	e = db.QueryRow("SELECT id FROM create_ops WHERE state='succeeded'").Scan(&id)
	if e == nil {
		e = db.QueryRow("SELECT id FROM create_ops WHERE state='prepared'").Scan(&prepared)
	}
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	socket = cfg.Transport.Socket
	stop = start()
	runClient(transportLabInput{ID: id})
	stop()
	invoke(false, "-state", state, "-backup-journal", filepath.Join(state, "journal.db-wal"))
	invoke(true, "-state", state, "-backup-journal", archive)
	rawArchive := read(archive)
	if len(rawArchive) < 8 || string(rawArchive[:8]) != "SWCRBAK1" {
		t.Fatal("backup envelope missing")
	}
	invoke(false, "-state", state, "-backup-journal", archive)
	if !bytes.Equal(rawArchive, read(archive)) {
		t.Fatal("backup overwritten")
	}
	invoke(false, "-state", state, "-restore-journal", archive)
	sourceState := state
	state = t.TempDir()
	for _, name := range []string{"journal.key", "issuer.pem", "writer.password", "ca.pem"} {
		write(name, read(filepath.Join(sourceState, name)))
	}
	socket = filepath.Join(socketDir, "recovery.sock")
	cfg.Transport.Socket = socket
	save()
	tampered := filepath.Join(archiveDir, "tampered.backup")
	rawArchive[len(rawArchive)-1] ^= 1
	if e = os.WriteFile(tampered, rawArchive, 0600); e != nil {
		t.Fatal(e)
	}
	invoke(false, "-state", state, "-restore-journal", tampered)
	write("journal.key", wrong)
	invoke(false, "-state", state, "-restore-journal", archive)
	write("journal.key", key)
	if _, e = os.Lstat(filepath.Join(state, "journal.db")); !os.IsNotExist(e) {
		t.Fatal("failed restore published a journal")
	}
	invoke(true, "-state", state, "-restore-journal", archive)
	restoredFile := filepath.Join(state, "journal.db")
	restoredBytes := read(restoredFile)
	stop = start()
	runClient(transportLabInput{ID: id, Recovery: true})
	runClient(transportLabInput{ID: prepared, Recovery: true, PrepareOnly: true})
	stop()
	if !bytes.Equal(restoredBytes, read(restoredFile)) {
		t.Fatal("recovery requests changed the journal")
	}
	// A SQLite tool resetting only the version must not turn recovery into an active journal.
	db, e = sql.Open("sqlite", "file:"+restoredFile+"?mode=rw")
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`PRAGMA user_version=0`)
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	socket = filepath.Join(socketDir, "forbidden.sock")
	cfg.Transport.Socket = socket
	save()
	invoke(false, "-state", state, "-enable")
	if _, e = os.Lstat(socket); !os.IsNotExist(e) {
		t.Fatal("downgraded recovery journal opened a socket")
	}
}
