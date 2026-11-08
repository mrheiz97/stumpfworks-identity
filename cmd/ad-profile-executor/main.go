package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adprofile"
)

type configuration struct {
	Directory                             adprofile.Config
	Driver, DatabaseFile, KeyFile, Socket string
}

func run() error {
	path := flag.String("config", "", "private executor JSON configuration (disabled by default)")
	initialize := flag.Bool("initialize-journal", false, "explicitly create a NEW executor journal, without AD contact")
	flag.Parse()
	if *path == "" {
		fmt.Println("AD profile editing disabled")
		return nil
	}
	if runtime.GOOS != "linux" {
		return adprofile.ErrDenied
	}
	raw, e := privateFile(*path)
	if e != nil {
		return e
	}
	var cfg configuration
	if json.Unmarshal(raw, &cfg) != nil {
		return adprofile.ErrDenied
	}
	if !cfg.Directory.Enabled {
		fmt.Println("AD profile editing disabled")
		return nil
	}
	if cfg.Directory.Validate() != nil {
		return adprofile.ErrDenied
	}
	key, e := privateFile(cfg.KeyFile)
	if e != nil {
		return e
	}
	dsn, e := privateFile(cfg.DatabaseFile)
	if e != nil {
		return e
	}
	// Stage 1 deliberately has one local, fenced executor. PostgreSQL journal
	// contracts are tested separately, but distributed execution is not enabled.
	if cfg.Driver != "sqlite" {
		return adprofile.ErrDenied
	}
	databaseURL := strings.TrimSpace(string(dsn))
	lockPath := cfg.DatabaseFile + ".executor.lock"
	if cfg.Driver == "sqlite" {
		if !filepath.IsAbs(databaseURL) || filepath.Clean(databaseURL) != databaseURL || strings.ContainsAny(databaseURL, "?%#\r\n") {
			return adprofile.ErrDenied
		}
		if protectedDirectory(filepath.Dir(databaseURL), false) != nil {
			return adprofile.ErrDenied
		}
		if st, err := os.Lstat(databaseURL); err == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
			return adprofile.ErrDenied
		}
		lockPath = databaseURL + ".executor.lock"
	}
	unlock, e := lockExecutor(lockPath)
	if e != nil {
		return e
	}
	defer unlock()
	db, e := sql.Open(cfg.Driver, databaseURL)
	if e != nil {
		return adprofile.ErrDenied
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.Exec(`PRAGMA synchronous=EXTRA; PRAGMA secure_delete=ON;`); e != nil {
		return adprofile.ErrDenied
	}
	journal, e := adprofile.NewJournal(db, key)
	if e != nil {
		return e
	}
	if *initialize {
		// Schema has no IF NOT EXISTS: existing journals must never be silently adopted.
		tx, e := db.Begin()
		if e != nil {
			return adprofile.ErrDenied
		}
		defer tx.Rollback()
		if _, e = tx.Exec(adprofile.Schema); e != nil {
			return adprofile.ErrDenied
		}
		return tx.Commit()
	}
	if _, e = privateFile(cfg.Directory.PasswordFile); e != nil {
		return e
	}
	if journal.Recover(context.Background()) != nil {
		return adprofile.ErrDenied
	}
	retentionCtx, stopRetention := context.WithCancel(context.Background())
	defer stopRetention()
	if journal.Erase(retentionCtx, time.Now()) != nil {
		return adprofile.ErrDenied
	}
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-retentionCtx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(retentionCtx, 5*time.Second)
				if journal.Erase(ctx, time.Now()) != nil {
					fmt.Fprintln(os.Stderr, "AD profile retention unavailable")
				}
				cancel()
			}
		}
	}()
	dir, e := adprofile.NewLDAP(cfg.Directory)
	if e != nil {
		return e
	}
	// No stale-socket deletion: an existing endpoint requires operator investigation.
	if protectedDirectory(filepath.Dir(cfg.Socket), true) != nil || !filepath.IsAbs(cfg.Socket) {
		return adprofile.ErrDenied
	}
	listener, e := net.Listen("unix", cfg.Socket)
	if e != nil {
		return adprofile.ErrDenied
	}
	defer listener.Close()
	if os.Chmod(cfg.Socket, 0660) != nil {
		return adprofile.ErrDenied
	}
	service := &adprofile.Service{Enabled: true, Policy: cfg.Directory.Revision, Directory: dir, Journal: journal}
	server := &http.Server{Handler: service, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, BaseContext: func(net.Listener) context.Context { return context.Background() }}
	return server.Serve(listener)
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "AD profile executor stopped: configuration or operation unavailable")
		os.Exit(1)
	}
}
