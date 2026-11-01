package clientupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RollbackFile struct {
	Component string `json:"component"`
	Target    string `json:"target"`
	Existed   bool   `json:"existed"`
	Mode      uint32 `json:"mode,omitempty"`
	Size      int64  `json:"size,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

type RollbackManifest struct {
	SchemaVersion int            `json:"schema_version"`
	PreparedAt    time.Time      `json:"prepared_at"`
	ForRelease    string         `json:"for_release"`
	Files         []RollbackFile `json:"files"`
}

func CreateRollback(root string, plan StagePlan, rollbackDir string, now time.Time) (RollbackManifest, error) {
	if root == "" || rollbackDir == "" {
		return RollbackManifest{}, errors.New("root and rollback directory are required")
	}
	if _, err := os.Lstat(rollbackDir); !os.IsNotExist(err) {
		return RollbackManifest{}, errors.New("rollback directory already exists")
	}
	temporary := rollbackDir + ".tmp"
	if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
		return RollbackManifest{}, errors.New("temporary rollback directory already exists")
	}
	if err := os.MkdirAll(filepath.Dir(rollbackDir), 0700); err != nil {
		return RollbackManifest{}, err
	}
	if err := os.Mkdir(temporary, 0700); err != nil {
		return RollbackManifest{}, err
	}
	cleanup := func() { _ = os.RemoveAll(temporary) }
	manifest := RollbackManifest{SchemaVersion: 1, PreparedAt: now.UTC(), ForRelease: plan.ReleaseVersion}
	seen := map[string]bool{}
	for _, component := range plan.Components {
		spec, ok := componentSpecs[component.Component]
		if !ok || component.Target != spec.Target || component.Mode != uint32(spec.Mode.Perm()) || seen[component.Component] {
			cleanup()
			return RollbackManifest{}, fmt.Errorf("invalid staged component %q", component.Component)
		}
		seen[component.Component] = true
		source := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(component.Target, "/")))
		info, err := os.Lstat(source)
		record := RollbackFile{Component: component.Component, Target: component.Target}
		if os.IsNotExist(err) {
			manifest.Files = append(manifest.Files, record)
			continue
		}
		if err != nil {
			cleanup()
			return RollbackManifest{}, err
		}
		if !info.Mode().IsRegular() {
			cleanup()
			return RollbackManifest{}, fmt.Errorf("rollback source for %s is not a regular file", component.Component)
		}
		if info.Size() > maxFileSize {
			cleanup()
			return RollbackManifest{}, fmt.Errorf("rollback source for %s exceeds size limit", component.Component)
		}
		destination := filepath.Join(temporary, "files", component.Component)
		if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			cleanup()
			return RollbackManifest{}, err
		}
		hash, err := copyRollbackFile(source, destination)
		if err != nil {
			cleanup()
			return RollbackManifest{}, err
		}
		record.Existed, record.Mode, record.Size, record.SHA256 = true, uint32(info.Mode().Perm()), info.Size(), hash
		manifest.Files = append(manifest.Files, record)
	}
	manifestFile, err := os.OpenFile(filepath.Join(temporary, "rollback.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		cleanup()
		return RollbackManifest{}, err
	}
	encoder := json.NewEncoder(manifestFile)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(manifest)
	if err == nil {
		err = manifestFile.Sync()
	}
	closeErr := manifestFile.Close()
	if err != nil {
		cleanup()
		return RollbackManifest{}, err
	}
	if closeErr != nil {
		cleanup()
		return RollbackManifest{}, closeErr
	}
	if _, statErr := os.Stat(filepath.Join(temporary, "files")); statErr == nil {
		if err = syncUpdateDirectory(filepath.Join(temporary, "files")); err != nil {
			cleanup()
			return RollbackManifest{}, err
		}
	}
	if err = syncUpdateDirectory(temporary); err != nil {
		cleanup()
		return RollbackManifest{}, err
	}
	if err = os.Rename(temporary, rollbackDir); err != nil {
		cleanup()
		return RollbackManifest{}, err
	}
	if err = syncUpdateDirectory(filepath.Dir(rollbackDir)); err != nil {
		return RollbackManifest{}, err
	}
	return manifest, nil
}

func copyRollbackFile(source, destination string) (string, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, maxFileSize+1))
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written > maxFileSize {
		return "", errors.New("rollback source exceeds size limit")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
