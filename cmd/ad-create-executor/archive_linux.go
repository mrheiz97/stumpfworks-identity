//go:build linux

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"golang.org/x/sys/unix"
)

const archiveMagic = "SWCRBAK1"
const maxJournalBytes = 64 << 20

func openJournal(path string) (*sql.DB, error) {
	return openJournalMode(path, "rw")
}

func openJournalMode(path, mode string) (*sql.DB, error) {
	options := url.Values{"mode": {mode}, "_pragma": {"synchronous(EXTRA)", "secure_delete(ON)", "trusted_schema(OFF)"}}
	dsn := url.URL{Scheme: "file", Path: path, RawQuery: options.Encode()}
	db, err := sql.Open("sqlite", dsn.String())
	if err == nil {
		db.SetMaxOpenConns(1)
	}
	return db, err
}

func checkSidecars(dir int, absent bool) error {
	for _, name := range []string{"journal.db-journal", "journal.db-wal", "journal.db-shm"} {
		file, err := privateFile(dir, name, unix.O_RDONLY)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		file.Close()
		if absent {
			return adcreate.ErrDenied
		}
	}
	return nil
}

func verifyJournal(db *sql.DB, binding []byte) (bool, error) {
	if err := verifySchema(db); err != nil {
		return false, err
	}
	var stored []byte
	var version int
	if db.QueryRow(`SELECT binding FROM executor_binding WHERE id=1`).Scan(&stored) != nil ||
		db.QueryRow(`PRAGMA user_version`).Scan(&version) != nil || (version != 0 && version != 1) {
		return false, adcreate.ErrDenied
	}
	if version == 1 {
		binding = recoveryBinding(binding)
	}
	if !hmac.Equal(stored, binding) {
		return false, adcreate.ErrDenied
	}
	return version == 1, nil
}

func recoveryBinding(binding []byte) []byte {
	mac := hmac.New(sha256.New, binding)
	mac.Write([]byte("identity-create-recovery-only-v1"))
	return mac.Sum(nil)
}

func checkIntegrity(db *sql.DB) error {
	var integrity string
	if db.QueryRow(`PRAGMA integrity_check(1)`).Scan(&integrity) != nil || integrity != "ok" {
		return adcreate.ErrDenied
	}
	return nil
}

func archiveCipher(key, binding []byte) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("identity-create-backup-v1:"))
	mac.Write(binding)
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func archiveParent(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, adcreate.ErrDenied
	}
	return privateDir(filepath.Dir(path))
}

// publish keeps an existing destination intact, even if it is a symlink.
func publish(temp string, dir int, name string) error {
	file, err := os.Open(temp)
	if err != nil {
		return err
	}
	err = file.Sync()
	file.Close()
	if err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, temp, dir, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

func backupJournal(state, archive string, key, binding []byte, db *sql.DB) error {
	dir, err := archiveParent(archive)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var pages, pageSize int64
	if db.QueryRow(`PRAGMA page_count`).Scan(&pages) != nil || db.QueryRow(`PRAGMA page_size`).Scan(&pageSize) != nil ||
		pageSize <= 0 || pages <= 0 || pages > maxJournalBytes/pageSize {
		return adcreate.ErrDenied
	}
	if err = checkIntegrity(db); err != nil {
		return err
	}
	file, err := os.CreateTemp(state, ".snapshot-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	file.Close()
	if _, err = db.Exec(`VACUUM INTO ?`, file.Name()); err != nil {
		return err
	}
	snapshot, err := os.Open(file.Name())
	if err != nil {
		return err
	}
	plain, err := io.ReadAll(io.LimitReader(snapshot, maxJournalBytes+1))
	snapshot.Close()
	if err != nil || len(plain) > maxJournalBytes {
		return adcreate.ErrDenied
	}
	aead, err := archiveCipher(key, binding)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	output, err := os.CreateTemp(filepath.Dir(archive), ".archive-*")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	header := append([]byte(archiveMagic), nonce...)
	_, err = output.Write(aead.Seal(header, nonce, plain, []byte(archiveMagic)))
	closeErr := output.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return publish(output.Name(), dir, filepath.Base(archive))
}

func restoreJournal(state string, dir int, archive string, key, binding []byte) error {
	var existing unix.Stat_t
	if err := unix.Fstatat(dir, "journal.db", &existing, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return adcreate.ErrDenied
	}
	if err := checkSidecars(dir, true); err != nil {
		return err
	}
	source, err := archiveParent(archive)
	if err != nil {
		return err
	}
	defer unix.Close(source)
	file, err := privateFile(source, filepath.Base(archive), unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.Close()
	aead, err := archiveCipher(key, binding)
	if err != nil {
		return err
	}
	headerSize := len(archiveMagic) + aead.NonceSize()
	limit := maxJournalBytes + headerSize + aead.Overhead()
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(raw) < headerSize+aead.Overhead() || len(raw) > limit || !bytes.HasPrefix(raw, []byte(archiveMagic)) {
		return adcreate.ErrDenied
	}
	plain, err := aead.Open(nil, raw[len(archiveMagic):headerSize], raw[headerSize:], []byte(archiveMagic))
	if err != nil {
		return adcreate.ErrDenied
	}
	temp, err := os.CreateTemp(state, ".restore-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	_, err = temp.Write(plain)
	closeErr := temp.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	db, err := openJournal(temp.Name())
	if err != nil {
		return err
	}
	if err = markRecovery(db, binding); err != nil {
		db.Close()
		return err
	}
	if err = db.Close(); err != nil {
		return err
	}
	return publish(temp.Name(), dir, "journal.db")
}

func markRecovery(db *sql.DB, binding []byte) error {
	if _, err := verifyJournal(db, binding); err != nil {
		return err
	}
	if err := checkIntegrity(db); err != nil {
		return err
	}
	var mode string
	if db.QueryRow(`PRAGMA journal_mode=DELETE`).Scan(&mode) != nil || mode != "delete" {
		return adcreate.ErrDenied
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE executor_binding SET binding=? WHERE id=1`, recoveryBinding(binding)); err != nil {
		return err
	}
	if _, err = tx.Exec(`PRAGMA user_version=1`); err != nil {
		return err
	}
	return tx.Commit()
}
