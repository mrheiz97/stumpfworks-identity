package clientupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// VerifyReleaseAcceptance proves that a verified release is installed exactly
// as signed and that its complete rollback remains usable. It never changes an
// installation target or rollback file.
func VerifyReleaseAcceptance(root string, result Result, rollbackDir string) (StagePlan, error) {
	if root == "" || rollbackDir == "" {
		return StagePlan{}, errors.New("root and rollback directory are required")
	}
	plan := StagePlan{ReleaseVersion: result.Manifest.ReleaseVersion, Architecture: result.Manifest.Architecture}
	seen := map[string]bool{}
	for _, file := range result.Manifest.Files {
		spec, ok := componentSpecs[file.Component]
		if !ok || seen[file.Component] {
			return StagePlan{}, fmt.Errorf("invalid release component %q", file.Component)
		}
		seen[file.Component] = true
		target := rootedTarget(root, spec.Target)
		info, err := os.Lstat(target)
		if err != nil {
			return StagePlan{}, fmt.Errorf("installed component %s: %w", file.Component, err)
		}
		modeMismatch := runtime.GOOS != "windows" && info.Mode().Perm() != spec.Mode.Perm()
		if !info.Mode().IsRegular() || modeMismatch || info.Size() != file.Size {
			return StagePlan{}, fmt.Errorf("installed component %s metadata mismatch", file.Component)
		}
		hash, err := hashRegularFile(target, file.Size)
		if err != nil {
			return StagePlan{}, fmt.Errorf("installed component %s: %w", file.Component, err)
		}
		if !strings.EqualFold(hash, file.SHA256) {
			return StagePlan{}, fmt.Errorf("installed component %s hash mismatch", file.Component)
		}
		plan.Components = append(plan.Components, StagedComponent{Component: file.Component, Target: spec.Target, Mode: uint32(spec.Mode.Perm()), SHA256: file.SHA256, RestartLightDM: spec.RestartLightDM})
	}
	rollback, err := VerifyRollback(root, rollbackDir)
	if err != nil {
		return StagePlan{}, fmt.Errorf("rollback verification: %w", err)
	}
	if rollback.ForRelease != result.Manifest.ReleaseVersion || len(rollback.Files) != len(seen) {
		return StagePlan{}, errors.New("rollback does not match accepted release")
	}
	for _, file := range rollback.Files {
		if !seen[file.Component] {
			return StagePlan{}, errors.New("rollback does not match accepted components")
		}
	}
	return plan, nil
}

// VerifyRollback validates a rollback without preparing or applying it.
func VerifyRollback(root, rollbackDir string) (RollbackManifest, error) {
	manifest, err := loadRollbackManifest(rollbackDir)
	if err != nil {
		return RollbackManifest{}, err
	}
	seen := map[string]bool{}
	for _, file := range manifest.Files {
		spec, ok := componentSpecs[file.Component]
		if !ok || file.Target != spec.Target || seen[file.Component] {
			return RollbackManifest{}, fmt.Errorf("invalid rollback component %q", file.Component)
		}
		seen[file.Component] = true
		target := rootedTarget(root, file.Target)
		if info, statErr := os.Lstat(target); statErr == nil && !info.Mode().IsRegular() {
			return RollbackManifest{}, fmt.Errorf("restore target for %s is not a regular file", file.Component)
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return RollbackManifest{}, statErr
		}
		if !file.Existed {
			if file.Mode != 0 || file.Size != 0 || file.SHA256 != "" {
				return RollbackManifest{}, fmt.Errorf("invalid absent-file record for %s", file.Component)
			}
			continue
		}
		if file.Mode == 0 || file.Mode&^0777 != 0 || file.Size < 0 || file.Size > maxFileSize {
			return RollbackManifest{}, fmt.Errorf("invalid rollback metadata for %s", file.Component)
		}
		backup := filepath.Join(rollbackDir, "files", file.Component)
		info, statErr := os.Lstat(backup)
		if statErr != nil {
			return RollbackManifest{}, fmt.Errorf("rollback file %s: %w", file.Component, statErr)
		}
		if !info.Mode().IsRegular() || info.Size() != file.Size {
			return RollbackManifest{}, fmt.Errorf("rollback file %s metadata mismatch", file.Component)
		}
		hash, hashErr := hashRegularFile(backup, file.Size)
		if hashErr != nil {
			return RollbackManifest{}, fmt.Errorf("rollback file %s: %w", file.Component, hashErr)
		}
		if !strings.EqualFold(hash, file.SHA256) {
			return RollbackManifest{}, fmt.Errorf("rollback file %s hash mismatch", file.Component)
		}
	}
	return manifest, nil
}

func hashRegularFile(path string, expectedSize int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return "", err
	}
	if written != expectedSize {
		return "", errors.New("size mismatch")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
