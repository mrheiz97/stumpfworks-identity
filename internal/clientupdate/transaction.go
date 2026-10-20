package clientupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const DefaultTransactionPath = "/var/lib/stumpfworks-badge/update-transaction.json"

type UpdateTransaction struct {
	SchemaVersion  int       `json:"schema_version"`
	ReleaseVersion string    `json:"release_version"`
	RollbackDir    string    `json:"rollback_dir"`
	StartedAt      time.Time `json:"started_at"`
}

func WriteUpdateTransaction(path string, transaction UpdateTransaction) error {
	if path == "" || transaction.SchemaVersion != 1 || !validVersion(transaction.ReleaseVersion) || !filepath.IsAbs(transaction.RollbackDir) || transaction.StartedAt.IsZero() {
		return errors.New("invalid update transaction")
	}
	raw, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err = writeExclusive(temporary, raw, 0600); err != nil {
		return err
	}
	if err = os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func ReadUpdateTransaction(path string) (*UpdateTransaction, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 4096 {
		return nil, errors.New("update transaction exceeds size limit")
	}
	var transaction UpdateTransaction
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&transaction); err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("update transaction contains trailing data")
	}
	if transaction.SchemaVersion != 1 || !validVersion(transaction.ReleaseVersion) || !filepath.IsAbs(transaction.RollbackDir) || transaction.StartedAt.IsZero() {
		return nil, errors.New("invalid update transaction")
	}
	return &transaction, nil
}

func RecoverPendingUpdate(ctx context.Context, root, transactionPath, statePath string, runner CommandRunner) (bool, error) {
	transaction, err := ReadUpdateTransaction(transactionPath)
	if err != nil || transaction == nil {
		return false, err
	}
	backupRoot := rootedTarget(root, "/var/backups/stumpfworks-badge")
	relativeRollback, err := filepath.Rel(backupRoot, transaction.RollbackDir)
	if err != nil || relativeRollback == "." || relativeRollback == ".." || filepath.IsAbs(relativeRollback) || len(relativeRollback) > 3 && relativeRollback[:3] == ".."+string(filepath.Separator) {
		return true, errors.New("update transaction rollback is outside the managed backup directory")
	}
	manifest, err := loadRollbackManifest(transaction.RollbackDir)
	if err != nil {
		return true, err
	}
	if manifest.ForRelease != transaction.ReleaseVersion {
		return true, errors.New("update transaction does not match rollback manifest")
	}
	plan := StagePlan{ReleaseVersion: transaction.ReleaseVersion}
	seen := map[string]bool{}
	for _, file := range manifest.Files {
		spec, ok := componentSpecs[file.Component]
		if !ok || seen[file.Component] || file.Target != spec.Target {
			return true, errors.New("update transaction contains invalid rollback component")
		}
		seen[file.Component] = true
		plan.Components = append(plan.Components, StagedComponent{Component: file.Component, Target: file.Target, Mode: uint32(spec.Mode.Perm()), RestartLightDM: spec.RestartLightDM})
	}
	if err = RestoreRollback(root, transaction.RollbackDir); err != nil {
		return true, err
	}
	if err = WriteUpdateState(statePath, UpdateState{Version: plan.ReleaseVersion, Status: "failed", UpdatedAt: transaction.StartedAt, RollbackAvailable: true}); err != nil {
		return true, err
	}
	if err = PostInterruptedRecovery(ctx, plan, runner)(); err != nil {
		return true, err
	}
	if err = os.Remove(transactionPath); err != nil && !os.IsNotExist(err) {
		return true, err
	}
	return true, nil
}
