//go:build linux

package adprofile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreateipc"
)

type handoffCapture struct {
	*NativeCreate
	digest [32]byte
}

func (d *handoffCapture) Create(ctx context.Context, b adcreate.BoundRequest) (adcreate.Result, error) {
	result, err := d.NativeCreate.Create(ctx, b)
	if err == nil {
		d.digest = sha256.Sum256(b.Wire.Bytes[:len(b.Wire.Bytes)-ed25519.SignatureSize])
	}
	return result, err
}

func TestCreateJournalHandoffLab(t *testing.T) {
	phase := os.Getenv("IDENTITY_CREATE_JOURNAL_PHASE")
	if phase != "before" && phase != "after" && phase != "return" {
		t.Skip("isolated handoff fixture")
	}
	const state = "/tmp/identity-handoff-executor"
	ctx := context.Background()
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	write := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(state, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	invoke := func(ok bool, args ...string) {
		t.Helper()
		output, err := exec.Command("/tests/create-executor", append([]string{"-state", state}, args...)...).CombinedOutput()
		if (err == nil) != ok {
			t.Fatalf("%v unexpected result: %v %s", args, err, output)
		}
	}
	fixtureDir, fixturePath, epoch := "/tmp/native-cas", "/tmp/lab-config.json", uint64(1)
	if phase == "after" {
		fixtureDir, fixturePath, epoch = createFixturePaths()
	}
	if phase == "return" {
		epoch = 3
	}
	var cfg struct {
		Directory Config
		Pins      CreatePins
		OU        string
		Transport adcreateipc.Config
	}
	var data struct{ Config Config }
	var pins nativePins
	if json.Unmarshal(read(fixturePath), &data) != nil || json.Unmarshal(read(fixtureDir+"/pins.json"), &pins) != nil {
		t.Fatal("fixture")
	}
	cfg.Directory = data.Config
	cfg.Pins = CreatePins{ActorGUID: pins.ActorGUID, ActorSID: pins.ActorSID, WriterGUID: pins.WriterGUID,
		ReceiptPublic: pins.ReceiptPublic, Scope: pins.Scope, Epoch: epoch}
	cfg.OU = string(read(fixtureDir + "/create-ou"))
	cfg.Transport.Enabled = true
	config, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	issuer := read(fixtureDir + "/issuer.pem")
	password := read(cfg.Directory.PasswordFile)
	dbPath := state + "/journal.db"
	openDB := func() *sql.DB {
		t.Helper()
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	if phase == "before" {
		if err := os.Mkdir(state, 0700); err != nil {
			t.Fatal(err)
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		write("journal.key", key)
		write("config.json", config)
		write("issuer.pem", issuer)
		write("writer.password", password)
		write("ca.pem", read(cfg.Directory.CAFile))
		invoke(true, "-initialize-journal")
	} else {
		write("next-config.json", config)
		write("next-issuer.pem", issuer)
		if phase == "after" {
			db := openDB()
			// Synthetic negative fixture: an unresolved dispatch must leave the
			// original journal untouched even after native promotion.
			if _, err := db.Exec(`UPDATE create_ops SET state='uncertain'`); err != nil {
				t.Fatal(err)
			}
			invoke(false, "-handoff-journal")
			var state string
			if db.QueryRow(`SELECT state FROM create_ops`).Scan(&state) != nil || state != "uncertain" {
				t.Fatal("unresolved claim changed")
			}
			if _, err := db.Exec(`UPDATE create_ops SET state='prepared'`); err != nil {
				t.Fatal(err)
			}
		}
		before := read(dbPath)
		write("next-issuer.pem", read(state+"/issuer.pem"))
		invoke(false, "-handoff-journal")
		if !bytes.Equal(before, read(dbPath)) {
			t.Fatal("failed target proof changed the journal")
		}
		write("next-issuer.pem", issuer)
		invoke(true, "-handoff-journal")
		invoke(false, "-handoff-journal") // old config cannot rebind again
		invoke(false, "-enable")          // interrupted before staged configuration install
		invoke(false, "-backup-journal", filepath.Join(t.TempDir(), "stale.archive"))
		write("config.json", config)
		write("issuer.pem", issuer)
	}
	block, _ := pem.Decode(issuer)
	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	backend, scope, err := NewNativeCreate(cfg.Directory, cfg.Pins, cfg.OU, rawKey.(ed25519.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	db := openDB()
	capture := &handoffCapture{NativeCreate: backend}
	service, err := adcreate.New(db, read(state+"/journal.key"), scope, capture)
	if err != nil {
		t.Fatal(err)
	}
	service.Enabled = true
	input := adcreate.Input{Name: "handoffheld", DisplayName: "Handoff Held"}
	if phase == "before" {
		if _, err = service.Prepare(ctx, "operator", string(password), input); err != nil {
			t.Fatal(err)
		}
		return
	}
	if phase == "return" {
		if claimSnapshot(t, db) != string(read(state+"/claims-before-return")) {
			t.Fatal("claim identities changed during return")
		}
		checkReturn(t, db, service, string(password))
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		checkReturnedArchive(t, state, string(password))
		return
	}
	var id string
	if db.QueryRow(`SELECT id FROM create_ops`).Scan(&id) != nil {
		t.Fatal("old operation missing")
	}
	old, err := service.Action(ctx, "operator", string(password), id, "status", "")
	if err != nil || old.State != "cancelled" || old.Plan.Scope.Epoch != 1 {
		t.Fatal("old plan must remain readable and cancelled", err)
	}
	var events int
	if db.QueryRow(`SELECT count(*) FROM create_audit WHERE (id=? AND event='handoff_cancelled')
		OR (id='' AND event='handoff_rebound')`, id).Scan(&events) != nil || events != 2 {
		t.Fatal("handoff audit missing")
	}
	if _, err = service.Action(ctx, "operator", string(password), id, "confirm", old.Plan.Digest); err == nil {
		t.Fatal("old plan replay")
	}
	if _, err = service.Prepare(ctx, "operator", string(password), input); err == nil {
		t.Fatal("reservation lost")
	}
	fresh, err := service.Prepare(ctx, "operator", string(password), adcreate.Input{Name: "handoffnext", DisplayName: "Handoff Next"})
	if err != nil {
		t.Fatal(err)
	}
	done, err := service.Action(ctx, "operator", string(password), fresh.Plan.ID, "confirm", fresh.Plan.Digest)
	if err != nil || done.State != "succeeded" {
		t.Fatal("create through rebound journal", err)
	}
	if os.Getenv("IDENTITY_CREATE_RETURN_LAB") == "1" {
		evidence, err := service.Action(ctx, "operator", string(password), fresh.Plan.ID, "evidence", "")
		if err != nil || evidence.Evidence == nil || *evidence.Evidence != done.Result {
			t.Fatal("authenticated DC2 evidence", err)
		}
		record, err := json.Marshal(map[string]string{"guid": done.Result.GUID, "digest": hex.EncodeToString(capture.digest[:])})
		if err != nil {
			t.Fatal(err)
		}
		write("dc2-evidence.json", record)
		if _, err = service.Prepare(ctx, "operator", string(password), adcreate.Input{Name: "returnheld", DisplayName: "Return Held"}); err != nil {
			t.Fatal(err)
		}
		write("claims-before-return", []byte(claimSnapshot(t, db)))
	}
}

func checkReturnedArchive(t *testing.T, state, password string) {
	t.Helper()
	run := func(dir string, ok bool, args ...string) {
		t.Helper()
		raw, err := exec.Command("/tests/create-executor", append([]string{"-state", dir}, args...)...).CombinedOutput()
		if (err == nil) != ok {
			t.Fatalf("%v: %v %s", args, err, raw)
		}
	}
	archive := filepath.Join(t.TempDir(), "epoch3.archive")
	run(state, true, "-backup-journal", archive)
	run(state, false, "-restore-journal", archive)
	recovery := t.TempDir()
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	write := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(recovery, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"journal.key", "issuer.pem", "writer.password", "ca.pem", "config.json"} {
		write(name, read(filepath.Join(state, name)))
	}
	socketDir, err := os.MkdirTemp("/tmp", "handoff-restore-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	if os.Chown(socketDir, 0, 65534) != nil || os.Chmod(socketDir, 0750) != nil {
		t.Fatal("recovery socket permissions")
	}
	socket := filepath.Join(socketDir, "executor.sock")
	var cfg struct {
		Directory Config
		Pins      CreatePins
		OU        string
		Transport adcreateipc.Config
	}
	if json.Unmarshal(read(filepath.Join(state, "config.json")), &cfg) != nil {
		t.Fatal("config")
	}
	current := cfg.Pins.Epoch
	cfg.Transport = adcreateipc.Config{Enabled: true, Socket: socket,
		Owner: &adcreateipc.Identity{UID: 0, GID: 65534}, Peer: &adcreateipc.Identity{UID: 65534, GID: 65534}}
	save := func() {
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		write("config.json", raw)
	}
	cfg.Pins.Epoch = 2
	save()
	run(recovery, false, "-restore-journal", archive)
	cfg.Pins.Epoch = current
	save()
	run(recovery, true, "-restore-journal", archive)
	run(recovery, false, "-handoff-journal")
	journal := filepath.Join(recovery, "journal.db")
	original := read(journal)
	open := func(path string) *sql.DB {
		db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	db := open(journal)
	if claimSnapshot(t, db) != claimSnapshot(t, open(filepath.Join(state, "journal.db"))) {
		t.Fatal("restore lost claims")
	}
	var id string
	if db.QueryRow(`SELECT id FROM create_ops ORDER BY rowid DESC LIMIT 1`).Scan(&id) != nil {
		t.Fatal("restored terminal operation missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, "/tests/create-executor", "-state", recovery, "-enable")
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	for {
		conn, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if ctx.Err() != nil {
			t.Fatal("recovery listener unavailable")
		}
		time.Sleep(25 * time.Millisecond)
	}
	input, err := json.Marshal(transportLabInput{Username: "operator", Password: password, ID: id, Recovery: true})
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCreateTransportChild$")
	child.Env = append(os.Environ(), "IDENTITY_CREATE_TRANSPORT_CHILD=1", "IDENTITY_CREATE_TRANSPORT_SOCKET="+socket)
	child.Stdin = bytes.NewReader(input)
	setCreateChildIdentity(child)
	if raw, err := child.CombinedOutput(); err != nil {
		t.Fatalf("recovery probe: %v %s", err, raw)
	}
	if !bytes.Equal(original, read(journal)) {
		t.Fatal("recovery modified restored journal")
	}
}

func claimSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var snapshot string
	if db.QueryRow(`SELECT group_concat(name || ':' || id, '|')
		FROM (SELECT name,id FROM create_names ORDER BY name)`).Scan(&snapshot) != nil {
		t.Fatal("cannot read claim snapshot")
	}
	return snapshot
}

func checkReturn(t *testing.T, db *sql.DB, service *adcreate.Service, password string) {
	t.Helper()
	ctx := context.Background()
	for index, name := range []string{"handoffheld", "handoffnext", "returnheld"} {
		var id string
		if db.QueryRow(`SELECT id FROM create_ops ORDER BY rowid LIMIT 1 OFFSET ?`, index).Scan(&id) != nil {
			t.Fatal("historical operation missing")
		}
		op, err := service.Action(ctx, "operator", password, id, "status", "")
		expected, epoch := "cancelled", uint64(2)
		if index == 0 {
			epoch = 1
		} else if index == 1 {
			expected = "succeeded"
		}
		if err != nil || op.State != expected || op.Plan.Scope.Epoch != epoch || op.Plan.Input.Name != name {
			t.Fatal("historical result changed", name, err)
		}
		if _, err = service.Action(ctx, "operator", password, id, "confirm", op.Plan.Digest); err == nil {
			t.Fatal("old operation replayed", name)
		}
		if _, err = service.Prepare(ctx, "operator", password, adcreate.Input{Name: name, DisplayName: "Duplicate"}); err == nil {
			t.Fatal("historical name reused", name)
		}
	}
	var claims, handoffs int
	if db.QueryRow(`SELECT count(*) FROM create_names`).Scan(&claims) != nil || claims != 6 ||
		db.QueryRow(`SELECT count(*) FROM create_audit WHERE event='handoff_rebound'`).Scan(&handoffs) != nil || handoffs != 2 {
		t.Fatal("journal claims or audit lost")
	}
	fresh, err := service.Prepare(ctx, "operator", password, adcreate.Input{Name: "returnnext", DisplayName: "Return Next"})
	if err != nil || fresh.Plan.Scope.Epoch != 3 {
		t.Fatal("prepare on returned route", err)
	}
	done, err := service.Action(ctx, "operator", password, fresh.Plan.ID, "confirm", fresh.Plan.Digest)
	if err != nil || done.State != "succeeded" {
		t.Fatal("create on returned route", err)
	}
}
