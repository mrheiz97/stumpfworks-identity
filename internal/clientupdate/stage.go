package clientupdate

import (
	"archive/zip"
	"crypto/ed25519"
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

type ComponentSpec struct {
	Target         string      `json:"target"`
	Mode           os.FileMode `json:"mode"`
	RestartLightDM bool        `json:"restart_lightdm"`
}

var componentSpecs = map[string]ComponentSpec{
	"sw-badge-native-greeter":         {"/usr/local/bin/sw-badge-native-greeter", 0755, true},
	"sw-badge-pam-helper":             {"/usr/local/libexec/sw-badge-pam-helper", 0755, false},
	"sw-badge-client-status":          {"/usr/local/libexec/sw-badge-client-status", 0755, false},
	"sw-badge-client-diagnostics":     {"/usr/local/sbin/sw-badge-client-diagnostics", 0755, false},
	"sw-badge-client-updater":         {"/usr/local/sbin/sw-badge-client-updater", 0755, false},
	"sw-badge-native-greeter-wrapper": {"/usr/local/bin/sw-badge-native-greeter-wrapper", 0755, true},
	"sw-badge-pam-helper-wrapper":     {"/usr/local/libexec/sw-badge-pam-helper-wrapper", 0755, false},
	"swbadge-client-status.service":   {"/etc/systemd/system/swbadge-client-status.service", 0644, false},
	"swbadge-client-status.timer":     {"/etc/systemd/system/swbadge-client-status.timer", 0644, false},
}

type StagedComponent struct {
	Component      string `json:"component"`
	Target         string `json:"target"`
	Mode           uint32 `json:"mode"`
	SHA256         string `json:"sha256"`
	RestartLightDM bool   `json:"restart_lightdm"`
}

type StagePlan struct {
	ReleaseVersion string            `json:"release_version"`
	Architecture   string            `json:"architecture"`
	Components     []StagedComponent `json:"components"`
}

func VerifyAndStage(packagePath string, publicKey ed25519.PublicKey, architecture, currentVersion, stageDir string) (StagePlan, error) {
	result, err := VerifyPackage(packagePath, publicKey, architecture, currentVersion)
	if err != nil {
		return StagePlan{}, err
	}
	if stageDir == "" {
		return StagePlan{}, errors.New("stage directory is required")
	}
	if _, err = os.Lstat(stageDir); !os.IsNotExist(err) {
		return StagePlan{}, errors.New("stage directory already exists")
	}
	temporary := stageDir + ".tmp"
	if _, err = os.Lstat(temporary); !os.IsNotExist(err) {
		return StagePlan{}, errors.New("temporary stage directory already exists")
	}
	if err = os.MkdirAll(filepath.Dir(stageDir), 0700); err != nil {
		return StagePlan{}, err
	}
	if err = os.Mkdir(temporary, 0700); err != nil {
		return StagePlan{}, err
	}
	cleanup := func() { _ = os.RemoveAll(temporary) }
	archive, err := zip.OpenReader(packagePath)
	if err != nil {
		cleanup()
		return StagePlan{}, err
	}
	defer archive.Close()
	entries := map[string]*zip.File{}
	for _, entry := range archive.File {
		entries[entry.Name] = entry
	}
	files := map[string]File{}
	for _, file := range result.Manifest.Files {
		files[file.Component] = file
	}
	plan := StagePlan{ReleaseVersion: result.Manifest.ReleaseVersion, Architecture: result.Manifest.Architecture}
	for _, component := range result.Files {
		manifestFile, spec := files[component], componentSpecs[component]
		destination := filepath.Join(temporary, "payload", component)
		if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			cleanup()
			return StagePlan{}, err
		}
		if err = stageEntry(entries["payload/"+component], destination, manifestFile, spec.Mode); err != nil {
			cleanup()
			return StagePlan{}, fmt.Errorf("stage %s: %w", component, err)
		}
		plan.Components = append(plan.Components, StagedComponent{Component: component, Target: spec.Target, Mode: uint32(spec.Mode.Perm()), SHA256: manifestFile.SHA256, RestartLightDM: spec.RestartLightDM})
	}
	planFile, err := os.OpenFile(filepath.Join(temporary, "stage-plan.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		cleanup()
		return StagePlan{}, err
	}
	encoder := json.NewEncoder(planFile)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(plan)
	closeErr := planFile.Close()
	if err != nil {
		cleanup()
		return StagePlan{}, err
	}
	if closeErr != nil {
		cleanup()
		return StagePlan{}, closeErr
	}
	if err = os.Rename(temporary, stageDir); err != nil {
		cleanup()
		return StagePlan{}, err
	}
	return plan, nil
}

func stageEntry(entry *zip.File, destination string, manifest File, mode os.FileMode) error {
	if entry == nil {
		return errors.New("payload entry is missing")
	}
	reader, err := entry.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(reader, manifest.Size+1))
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != manifest.Size || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), manifest.SHA256) {
		return errors.New("payload changed after verification")
	}
	return os.Chmod(destination, mode)
}
