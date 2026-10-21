package clientupdate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func RestoreRollback(root, rollbackDir string) error {
	return restoreRollback(root, rollbackDir, nil)
}

func restoreRollback(root, rollbackDir string, beforeApply func(int, RollbackFile) error) error {
	manifest, err := VerifyRollback(root, rollbackDir)
	if err != nil {
		return err
	}
	preparedDir := filepath.Join(rollbackDir, ".restore-prepared")
	if err = os.RemoveAll(preparedDir); err != nil {
		return err
	}
	if err = os.Mkdir(preparedDir, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(preparedDir)
	for _, file := range manifest.Files {
		if !file.Existed {
			continue
		}
		backup := filepath.Join(rollbackDir, "files", file.Component)
		prepared := filepath.Join(preparedDir, file.Component)
		if err = copyAndVerify(backup, prepared, file.Size, file.SHA256, os.FileMode(file.Mode)); err != nil {
			return fmt.Errorf("rollback file %s: %w", file.Component, err)
		}
	}
	for index, file := range manifest.Files {
		if beforeApply != nil {
			if err = beforeApply(index, file); err != nil {
				return err
			}
		}
		target := rootedTarget(root, file.Target)
		if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if !file.Existed {
			if err = os.Remove(target); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		prepared := filepath.Join(preparedDir, file.Component)
		replacement := target + ".swbadge-restore-new"
		if err = copyAndVerify(prepared, replacement, file.Size, file.SHA256, os.FileMode(file.Mode)); err != nil {
			_ = os.Remove(replacement)
			return err
		}
		if err = os.Rename(replacement, target); err != nil {
			_ = os.Remove(replacement)
			return err
		}
	}
	return nil
}

func loadRollbackManifest(rollbackDir string) (RollbackManifest, error) {
	raw, err := os.ReadFile(filepath.Join(rollbackDir, "rollback.json"))
	if err != nil {
		return RollbackManifest{}, err
	}
	if len(raw) > maxManifestSize {
		return RollbackManifest{}, errors.New("rollback manifest exceeds size limit")
	}
	var manifest RollbackManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		return RollbackManifest{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return RollbackManifest{}, errors.New("rollback manifest contains trailing data")
	}
	if manifest.SchemaVersion != 1 || manifest.PreparedAt.IsZero() || manifest.ForRelease == "" || len(manifest.Files) == 0 {
		return RollbackManifest{}, errors.New("rollback manifest is incomplete")
	}
	return manifest, nil
}

func rootedTarget(root, target string) string {
	return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(target, "/")))
}

func copyAndVerify(source, destination string, size int64, expectedHash string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, maxFileSize+1))
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != size || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedHash) {
		_ = os.Remove(destination)
		return errors.New("size or hash mismatch")
	}
	return os.Chmod(destination, mode)
}
