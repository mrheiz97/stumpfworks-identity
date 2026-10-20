package clientupdate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func InstallStaged(root, stageDir, rollbackDir string, now time.Time, allowLightDMMaintenance bool, healthCheck, rollbackRecovery func() error) error {
	return InstallStagedWithTransaction(root, stageDir, rollbackDir, "", now, allowLightDMMaintenance, healthCheck, rollbackRecovery)
}

func InstallStagedWithTransaction(root, stageDir, rollbackDir, transactionPath string, now time.Time, allowLightDMMaintenance bool, healthCheck, rollbackRecovery func() error) error {
	if healthCheck == nil {
		return errors.New("post-install health check is required")
	}
	if rollbackRecovery == nil {
		return errors.New("post-rollback recovery check is required")
	}
	return installStaged(root, stageDir, rollbackDir, transactionPath, now, allowLightDMMaintenance, nil, healthCheck, rollbackRecovery)
}

func installStaged(root, stageDir, rollbackDir, transactionPath string, now time.Time, allowLightDMMaintenance bool, beforeApply func(int, StagedComponent) error, healthCheck, rollbackRecovery func() error) error {
	plan, err := loadStagePlan(stageDir)
	if err != nil {
		return err
	}
	if RequiresLightDMMaintenance(plan) && !allowLightDMMaintenance {
		return errors.New("update contains greeter components and requires an explicit LightDM maintenance window")
	}
	if err = validateStagedPayload(stageDir, plan); err != nil {
		return err
	}
	if _, err = CreateRollback(root, plan, rollbackDir, now); err != nil {
		return fmt.Errorf("prepare rollback: %w", err)
	}
	if transactionPath != "" {
		if err = WriteUpdateTransaction(transactionPath, UpdateTransaction{SchemaVersion: 1, ReleaseVersion: plan.ReleaseVersion, RollbackDir: rollbackDir, StartedAt: now.UTC()}); err != nil {
			return fmt.Errorf("record update transaction: %w", err)
		}
	}
	installPrepared := filepath.Join(stageDir, ".install-prepared")
	if err = os.RemoveAll(installPrepared); err != nil {
		return rollbackInstallFailure(root, rollbackDir, transactionPath, err, rollbackRecovery)
	}
	if err = os.Mkdir(installPrepared, 0700); err != nil {
		return rollbackInstallFailure(root, rollbackDir, transactionPath, err, rollbackRecovery)
	}
	defer os.RemoveAll(installPrepared)
	for _, component := range plan.Components {
		source := filepath.Join(stageDir, "payload", component.Component)
		destination := filepath.Join(installPrepared, component.Component)
		if err = copyAndVerify(source, destination, fileSize(source), component.SHA256, os.FileMode(component.Mode)); err != nil {
			return rollbackInstallFailure(root, rollbackDir, transactionPath, fmt.Errorf("prepare %s: %w", component.Component, err), rollbackRecovery)
		}
	}
	for index, component := range plan.Components {
		if beforeApply != nil {
			if err = beforeApply(index, component); err != nil {
				return rollbackInstallFailure(root, rollbackDir, transactionPath, err, rollbackRecovery)
			}
		}
		target := rootedTarget(root, component.Target)
		if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return rollbackInstallFailure(root, rollbackDir, transactionPath, err, rollbackRecovery)
		}
		replacement := target + ".swbadge-install-new"
		if err = copyAndVerify(filepath.Join(installPrepared, component.Component), replacement, fileSize(filepath.Join(installPrepared, component.Component)), component.SHA256, os.FileMode(component.Mode)); err != nil {
			_ = os.Remove(replacement)
			return rollbackInstallFailure(root, rollbackDir, transactionPath, err, rollbackRecovery)
		}
		if err = os.Rename(replacement, target); err != nil {
			_ = os.Remove(replacement)
			return rollbackInstallFailure(root, rollbackDir, transactionPath, err, rollbackRecovery)
		}
	}
	if healthCheck == nil {
		return rollbackInstallFailure(root, rollbackDir, transactionPath, errors.New("post-install health check is required"), rollbackRecovery)
	}
	if err = healthCheck(); err != nil {
		return rollbackInstallFailure(root, rollbackDir, transactionPath, fmt.Errorf("post-install health check failed: %w", err), rollbackRecovery)
	}
	if transactionPath != "" {
		if err = os.Remove(transactionPath); err != nil {
			return rollbackInstallFailure(root, rollbackDir, transactionPath, fmt.Errorf("complete update transaction: %w", err), rollbackRecovery)
		}
	}
	return nil
}

func RequiresLightDMMaintenance(plan StagePlan) bool {
	for _, component := range plan.Components {
		if component.RestartLightDM {
			return true
		}
	}
	return false
}

func loadStagePlan(stageDir string) (StagePlan, error) {
	raw, err := os.ReadFile(filepath.Join(stageDir, "stage-plan.json"))
	if err != nil {
		return StagePlan{}, err
	}
	if len(raw) > maxManifestSize {
		return StagePlan{}, errors.New("stage plan exceeds size limit")
	}
	var plan StagePlan
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&plan); err != nil {
		return StagePlan{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return StagePlan{}, errors.New("stage plan contains trailing data")
	}
	if !validVersion(plan.ReleaseVersion) || plan.Architecture == "" || len(plan.Components) == 0 {
		return StagePlan{}, errors.New("stage plan is incomplete")
	}
	return plan, nil
}

func validateStagedPayload(stageDir string, plan StagePlan) error {
	seen := map[string]bool{}
	for _, component := range plan.Components {
		spec, ok := componentSpecs[component.Component]
		if !ok || seen[component.Component] || component.Target != spec.Target || component.Mode != uint32(spec.Mode.Perm()) || component.RestartLightDM != spec.RestartLightDM {
			return fmt.Errorf("invalid staged component %q", component.Component)
		}
		seen[component.Component] = true
		if len(component.SHA256) != 64 {
			return fmt.Errorf("invalid staged hash for %s", component.Component)
		}
		path := filepath.Join(stageDir, "payload", component.Component)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > maxFileSize {
			return fmt.Errorf("invalid staged payload for %s", component.Component)
		}
		temporary := filepath.Join(stageDir, ".validate-"+component.Component)
		if err = copyAndVerify(path, temporary, info.Size(), component.SHA256, 0600); err != nil {
			_ = os.Remove(temporary)
			return fmt.Errorf("validate %s: %w", component.Component, err)
		}
		_ = os.Remove(temporary)
	}
	return nil
}

func rollbackInstallFailure(root, rollbackDir, transactionPath string, installErr error, rollbackRecovery func() error) error {
	if rollbackErr := RestoreRollback(root, rollbackDir); rollbackErr != nil {
		return fmt.Errorf("installation failed: %v; automatic rollback failed: %w", installErr, rollbackErr)
	}
	if rollbackRecovery == nil {
		return fmt.Errorf("installation failed and files were restored, but rollback recovery check is missing: %w", installErr)
	}
	if recoveryErr := rollbackRecovery(); recoveryErr != nil {
		return fmt.Errorf("installation failed: %v; files were restored, but rollback recovery failed: %w", installErr, recoveryErr)
	}
	if transactionPath != "" {
		if removeErr := os.Remove(transactionPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("installation failed and files were restored, but transaction cleanup failed: %v: %w", installErr, removeErr)
		}
	}
	return fmt.Errorf("installation failed and was rolled back: %w", installErr)
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}
