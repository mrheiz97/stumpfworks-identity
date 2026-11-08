//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreateipc"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adprofile"
	"golang.org/x/sys/unix"
)

type configuration struct {
	Directory adprofile.Config
	Pins      adprofile.CreatePins
	OU        string
	Transport adcreateipc.Config
}

func privateDir(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, adcreate.ErrDenied
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			unix.Close(fd)
			return -1, adcreate.ErrDenied
		}
		stickyTmp := i == 0 && part == "tmp" && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		owner := uint32(os.Geteuid())
		if (st.Uid != 0 && st.Uid != owner) || (!stickyTmp && st.Mode&0022 != 0) ||
			(i == len(parts)-1 && (st.Uid != owner || st.Mode&0777 != 0700)) {
			unix.Close(fd)
			return -1, adcreate.ErrDenied
		}
	}
	return fd, nil
}

func privateFile(dir int, name string, flags int) (*os.File, error) {
	fd, e := unix.Openat(dir, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		unix.Close(fd)
		return nil, adcreate.ErrDenied
	}
	return os.NewFile(uintptr(fd), name), nil
}

func readPrivate(dir int, name string) ([]byte, error) {
	f, e := privateFile(dir, name, unix.O_RDONLY)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return nil, adcreate.ErrDenied
	}
	return b, nil
}

func run(path string, initialize bool, backup, restore string, handoff bool) error {
	if err := start(path, initialize, backup, restore, handoff); err != nil {
		return errors.New("configuration, journal or isolated native backend unavailable")
	}
	return nil
}

func start(path string, initialize bool, backup, restore string, handoff bool) error {
	if (backup != "" && filepath.Dir(backup) == path) || (restore != "" && filepath.Dir(restore) == path) {
		return adcreate.ErrDenied
	}
	unix.Umask(0077)
	dir, e := privateDir(path)
	if e != nil {
		return e
	}
	defer unix.Close(dir)
	lock, e := privateFile(dir, "journal.lock", unix.O_RDWR|unix.O_CREAT)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return e
	}
	cfg, e := readConfiguration(dir, "config.json")
	if e != nil {
		return e
	}
	if handoff || (!initialize && backup == "" && restore == "" && cfg.Pins.FixedUPNSuffix == "") {
		interfaces, err := net.Interfaces()
		if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 ||
			(handoff && cfg.Pins.FixedUPNSuffix != "") {
			return adcreate.ErrDenied
		}
	}
	key, e := readPrivate(dir, "journal.key")
	if e != nil {
		return e
	}
	if len(key) != 32 {
		return adcreate.ErrDenied
	}
	binding, e := configurationBinding(cfg, key)
	if e != nil {
		return e
	}
	if restore != "" {
		return restoreJournal(path, dir, restore, key, binding)
	}
	if e = checkSidecars(dir, initialize); e != nil {
		return e
	}
	flags := unix.O_RDWR
	if initialize {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	journal, e := privateFile(dir, "journal.db", flags)
	if e != nil {
		return e
	}
	defer journal.Close()
	db, e := openJournal(filepath.Join(path, "journal.db"))
	if e != nil {
		return e
	}
	defer db.Close()
	if initialize {
		tx, e := db.Begin()
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if _, e = tx.Exec(adcreate.Schema + ";" + bindingSchema); e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO executor_binding VALUES(1,?)", binding); e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		return unix.Fsync(dir)
	}
	recovery, e := verifyJournal(db, binding)
	if e != nil {
		return e
	}
	if handoff {
		if recovery {
			return adcreate.ErrDenied
		}
		return handoffJournal(path, dir, db, cfg, key, binding)
	}
	if backup != "" {
		return backupJournal(path, backup, key, binding, db)
	}
	if recovery {
		if e = db.Close(); e != nil {
			return e
		}
		db, e = openJournalMode(filepath.Join(path, "journal.db"), "ro")
		if e != nil {
			return e
		}
		defer db.Close()
	}
	backend, scope, e := loadBackend(path, dir, cfg, "issuer.pem")
	if e != nil {
		return e
	}
	service, e := adcreate.New(db, key, scope, backend)
	if e != nil {
		return e
	}
	service.RecoveryOnly = recovery
	if !recovery {
		maintenance, stop := context.WithTimeout(context.Background(), 10*time.Second)
		e = service.Maintain(maintenance, time.Now())
		stop()
		if e != nil {
			return e
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
	defer cancel()
	probe, stop := context.WithTimeout(ctx, 10*time.Second)
	e = backend.Ready(probe)
	stop()
	if e != nil {
		return e
	}
	service.Enabled = true
	server, e := adcreateipc.Listen(cfg.Transport, service)
	if e != nil {
		return e
	}
	defer server.Close()
	maintenanceFailed := make(chan error, 1)
	if !recovery {
		maintenance, stop := context.WithCancel(ctx)
		drained := make(chan struct{})
		defer func() { stop(); <-drained }()
		go func() {
			defer close(drained)
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-maintenance.Done():
					return
				case now := <-ticker.C:
					attempt, cancel := context.WithTimeout(maintenance, 10*time.Second)
					err := service.Maintain(attempt, now)
					cancel()
					if err != nil && !errors.Is(err, adcreate.ErrMaintenanceBusy) && maintenance.Err() == nil {
						maintenanceFailed <- err
						return
					}
				}
			}
		}()
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	select {
	case e = <-done:
		return e
	case err := <-maintenanceFailed:
		server.Close()
		return errors.Join(err, <-done)
	case <-ctx.Done():
		drain, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		err := server.Shutdown(drain)
		if err != nil {
			server.Close()
		}
		return errors.Join(err, <-done)
	}
}

const bindingSchema = "CREATE TABLE executor_binding(id INTEGER PRIMARY KEY CHECK(id=1),binding BLOB NOT NULL)"

func readConfiguration(dir int, name string) (configuration, error) {
	var cfg configuration
	raw, e := readPrivate(dir, name)
	if e != nil {
		return cfg, e
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || !cfg.Transport.Enabled || !cfg.Directory.Enabled {
		return cfg, adcreate.ErrDenied
	}
	return cfg, nil
}

func configurationBinding(cfg configuration, key []byte) ([]byte, error) {
	cfg.Transport = adcreateipc.Config{}
	encoded, e := json.Marshal(cfg)
	if e != nil {
		return nil, e
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("identity-create-executor-v1:"))
	mac.Write(encoded)
	return mac.Sum(nil), nil
}

func verifySchema(db *sql.DB) error {
	expected := make(map[string]bool)
	for _, statement := range strings.Split(adcreate.Schema+";"+bindingSchema, ";") {
		if statement = strings.TrimSpace(statement); statement != "" {
			expected[statement] = true
		}
	}
	rows, e := db.Query("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var statement string
		if rows.Scan(&statement) != nil || !expected[statement] {
			return adcreate.ErrDenied
		}
		delete(expected, statement)
	}
	if len(expected) != 0 {
		return adcreate.ErrDenied
	}
	return rows.Err()
}

func loadBackend(path string, dir int, cfg configuration, issuer string) (*adprofile.NativeCreate, adcreate.Scope, error) {
	var scope adcreate.Scope
	signer, e := readPrivate(dir, issuer)
	if e != nil {
		return nil, scope, e
	}
	block, rest := pem.Decode(signer)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, scope, adcreate.ErrDenied
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, scope, e
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, scope, adcreate.ErrDenied
	}
	for _, name := range []string{"writer.password", "ca.pem"} {
		if _, e = readPrivate(dir, name); e != nil {
			return nil, scope, e
		}
	}
	cfg.Directory.PasswordFile = filepath.Join(path, "writer.password")
	cfg.Directory.CAFile = filepath.Join(path, "ca.pem")
	return adprofile.NewNativeCreate(cfg.Directory, cfg.Pins, cfg.OU, private)
}
