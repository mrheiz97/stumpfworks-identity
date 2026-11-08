//go:build linux

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"io"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"golang.org/x/sys/unix"
)

// handoffJournal runs offline under the executor's journal.lock. The isolated
// lab controller must already have promoted the target after DRS and receipts.
func handoffJournal(path string, dir int, db *sql.DB, old configuration, key, binding []byte) error {
	next, err := readConfiguration(dir, "next-config.json")
	if err != nil {
		return err
	}
	// Keep the journal's namespace and identity policy fixed. Only routing
	// and the DC's receipt keys/scope may change.
	comparable := next
	comparable.Directory.URL = old.Directory.URL
	comparable.Directory.DCIdentity = old.Directory.DCIdentity
	comparable.Pins.Epoch = old.Pins.Epoch
	comparable.Pins.ReceiptPublic = old.Pins.ReceiptPublic
	comparable.Pins.Scope = old.Pins.Scope
	samePolicy, err := configurationBinding(comparable, key)
	if err != nil || !bytes.Equal(samePolicy, binding) || old.Pins.Epoch == 0 ||
		next.Pins.Epoch <= old.Pins.Epoch || old.Directory.DCIdentity == next.Directory.DCIdentity ||
		!labRoutePair(old.Directory.URL, next.Directory.URL) {
		return adcreate.ErrDenied
	}
	nextBinding, err := configurationBinding(next, key)
	if err != nil {
		return err
	}
	authority, err := privateDir("/tmp/create-authority")
	if err != nil {
		return err
	}
	defer unix.Close(authority)
	lock, err := privateFile(authority, "lock", unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	route, err := privateFile(authority, "route", unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer route.Close()
	raw, err := io.ReadAll(io.LimitReader(route, 25))
	dc, parseErr := hex.DecodeString(next.Directory.DCIdentity)
	if err != nil || parseErr != nil || len(raw) != 24 || len(dc) != 16 ||
		binary.BigEndian.Uint64(raw[:8]) != next.Pins.Epoch || !bytes.Equal(raw[8:], dc) {
		return adcreate.ErrDenied
	}
	backend, _, err := loadBackend(path, dir, next, "next-issuer.pem")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = backend.Ready(ctx); err != nil {
		return err
	}
	return rebindJournal(ctx, db, binding, nextBinding, time.Now().Unix())
}

func labRoutePair(old, next string) bool {
	const first, second = "ldaps://dc1.profile.test:636", "ldaps://dc2.profile.test:636"
	return (old == first && next == second) || (old == second && next == first)
}

func rebindJournal(ctx context.Context, db *sql.DB, old, next []byte, now int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var blocked int
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM create_ops o WHERE state IN ('applying','uncertain')
		OR (state='prepared' AND EXISTS(SELECT 1 FROM create_dispatch d WHERE d.id=o.id)))`).Scan(&blocked); err != nil || blocked != 0 {
		return adcreate.ErrDenied
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO create_audit
		SELECT id,actor,'handoff_cancelled',? FROM create_ops WHERE state='prepared'`, now); err != nil {
		return err
	}
	// Retain even the unsent names. They must never become reusable merely
	// because the route changed. Historical plans and results stay sealed.
	if _, err = tx.ExecContext(ctx, `UPDATE create_ops SET state='cancelled' WHERE state='prepared'`); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE executor_binding SET binding=? WHERE id=1 AND binding=?`, next, old)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return adcreate.ErrDenied
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO create_audit VALUES('','','handoff_rebound',?)`, now); err != nil {
		return err
	}
	return tx.Commit()
}
