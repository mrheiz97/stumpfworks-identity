package clientupdate

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxManifestSize = 64 << 10
const maxFileSize = 64 << 20
const maxPackageSize = 256 << 20

var allowedComponents = map[string]bool{
	"sw-badge-native-greeter": true, "sw-badge-pam-helper": true,
	"sw-badge-client-status": true, "sw-badge-client-diagnostics": true,
	"sw-badge-client-updater":         true,
	"sw-badge-native-greeter-wrapper": true, "sw-badge-pam-helper-wrapper": true,
	"swbadge-client-status.service": true, "swbadge-client-status.timer": true,
}

type File struct {
	Component string `json:"component"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion  int       `json:"schema_version"`
	ReleaseVersion string    `json:"release_version"`
	Channel        string    `json:"channel"`
	Architecture   string    `json:"architecture"`
	MinimumVersion string    `json:"minimum_client_version"`
	CreatedAt      time.Time `json:"created_at"`
	Files          []File    `json:"files"`
}

type Result struct {
	Manifest Manifest
	Files    []string
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, errors.New("invalid base64 public key")
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key length")
	}
	return ed25519.PublicKey(decoded), nil
}

func VerifyPackage(path string, publicKey ed25519.PublicKey, expectedArchitecture, currentVersion string) (Result, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return Result{}, fmt.Errorf("open package: %w", err)
	}
	defer archive.Close()
	entries := map[string]*zip.File{}
	for _, entry := range archive.File {
		if len(entries) >= 32 {
			return Result{}, errors.New("package contains too many entries")
		}
		if entry.FileInfo().IsDir() || entry.Name != strings.ReplaceAll(entry.Name, "\\", "/") || strings.Contains(entry.Name, "..") || strings.HasPrefix(entry.Name, "/") {
			return Result{}, fmt.Errorf("unsafe package entry %q", entry.Name)
		}
		if _, exists := entries[entry.Name]; exists {
			return Result{}, fmt.Errorf("duplicate package entry %q", entry.Name)
		}
		entries[entry.Name] = entry
	}
	manifestBytes, err := readEntry(entries["manifest.json"], maxManifestSize)
	if err != nil {
		return Result{}, fmt.Errorf("manifest: %w", err)
	}
	signatureText, err := readEntry(entries["manifest.sig"], 1024)
	if err != nil {
		return Result{}, fmt.Errorf("signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Result{}, errors.New("invalid manifest signature encoding")
	}
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, manifestBytes, signature) {
		return Result{}, errors.New("manifest signature verification failed")
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		return Result{}, fmt.Errorf("decode manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Result{}, errors.New("manifest contains trailing data")
	}
	if err = validateManifest(manifest, expectedArchitecture, currentVersion); err != nil {
		return Result{}, err
	}
	listed := map[string]bool{"manifest.json": true, "manifest.sig": true}
	names := make([]string, 0, len(manifest.Files))
	var total int64
	for _, file := range manifest.Files {
		name := "payload/" + file.Component
		listed[name] = true
		names = append(names, file.Component)
		total += file.Size
		if total > maxPackageSize {
			return Result{}, errors.New("package payload exceeds size limit")
		}
		payload, err := readEntry(entries[name], file.Size)
		if err != nil {
			return Result{}, fmt.Errorf("component %s: %w", file.Component, err)
		}
		if int64(len(payload)) != file.Size {
			return Result{}, fmt.Errorf("component %s size mismatch", file.Component)
		}
		sum := sha256.Sum256(payload)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), file.SHA256) {
			return Result{}, fmt.Errorf("component %s hash mismatch", file.Component)
		}
	}
	for name := range entries {
		if !listed[name] {
			return Result{}, fmt.Errorf("unlisted package entry %q", name)
		}
	}
	sort.Strings(names)
	return Result{Manifest: manifest, Files: names}, nil
}

func readEntry(entry *zip.File, limit int64) ([]byte, error) {
	if entry == nil {
		return nil, errors.New("entry is missing")
	}
	if entry.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("entry exceeds size limit")
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("entry exceeds size limit")
	}
	return data, nil
}

func validateManifest(manifest Manifest, expectedArchitecture, currentVersion string) error {
	if manifest.SchemaVersion != 1 {
		return errors.New("unsupported manifest schema")
	}
	if !validVersion(manifest.ReleaseVersion) || !validVersion(manifest.MinimumVersion) {
		return errors.New("invalid release version")
	}
	if manifest.Channel != "development" && manifest.Channel != "stable" {
		return errors.New("invalid release channel")
	}
	if expectedArchitecture == "" {
		expectedArchitecture = runtime.GOOS + "-" + runtime.GOARCH
	}
	if manifest.Architecture != expectedArchitecture {
		return fmt.Errorf("package architecture %q does not match %q", manifest.Architecture, expectedArchitecture)
	}
	if manifest.CreatedAt.IsZero() || len(manifest.Files) == 0 {
		return errors.New("manifest is incomplete")
	}
	if currentVersion != "" {
		if !validVersion(currentVersion) {
			return errors.New("invalid current client version")
		}
		if compareVersions(currentVersion, manifest.MinimumVersion) < 0 {
			return fmt.Errorf("client version %q is below minimum %q", currentVersion, manifest.MinimumVersion)
		}
		if compareVersions(currentVersion, manifest.ReleaseVersion) >= 0 {
			return fmt.Errorf("release %q is not newer than client %q", manifest.ReleaseVersion, currentVersion)
		}
	}
	seen := map[string]bool{}
	for _, file := range manifest.Files {
		if !allowedComponents[file.Component] || seen[file.Component] {
			return fmt.Errorf("invalid component %q", file.Component)
		}
		seen[file.Component] = true
		if file.Size < 0 || file.Size > maxFileSize {
			return fmt.Errorf("invalid size for %s", file.Component)
		}
		decoded, err := hex.DecodeString(file.SHA256)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("invalid SHA-256 for %s", file.Component)
		}
	}
	return nil
}

func validVersion(value string) bool {
	value = strings.TrimPrefix(value, "v")
	if build := strings.IndexByte(value, '+'); build >= 0 {
		if build == len(value)-1 || !validIdentifiers(value[build+1:]) {
			return false
		}
		value = value[:build]
	}
	mainAndPre := strings.SplitN(value, "-", 2)
	main := mainAndPre[0]
	if len(mainAndPre) == 2 && !validIdentifiers(mainAndPre[1]) {
		return false
	}
	parts := strings.Split(main, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validIdentifiers(value string) bool {
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return false
			}
		}
	}
	return true
}

func compareVersions(left, right string) int {
	parse := func(value string) ([3]int, []string) {
		value = strings.TrimPrefix(value, "v")
		if i := strings.IndexByte(value, '+'); i >= 0 {
			value = value[:i]
		}
		pieces := strings.SplitN(value, "-", 2)
		numbers := strings.Split(pieces[0], ".")
		var out [3]int
		for i := range out {
			out[i], _ = strconv.Atoi(numbers[i])
		}
		if len(pieces) == 2 {
			return out, strings.Split(pieces[1], ".")
		}
		return out, nil
	}
	leftNumbers, leftPre := parse(left)
	rightNumbers, rightPre := parse(right)
	for i := range leftNumbers {
		if leftNumbers[i] < rightNumbers[i] {
			return -1
		}
		if leftNumbers[i] > rightNumbers[i] {
			return 1
		}
	}
	if leftPre == nil && rightPre == nil {
		return 0
	}
	if leftPre == nil {
		return 1
	}
	if rightPre == nil {
		return -1
	}
	for i := 0; i < len(leftPre) && i < len(rightPre); i++ {
		if leftPre[i] == rightPre[i] {
			continue
		}
		leftN, leftErr := strconv.Atoi(leftPre[i])
		rightN, rightErr := strconv.Atoi(rightPre[i])
		if leftErr == nil && rightErr == nil {
			if leftN < rightN {
				return -1
			}
			return 1
		}
		if leftErr == nil {
			return -1
		}
		if rightErr == nil {
			return 1
		}
		if leftPre[i] < rightPre[i] {
			return -1
		}
		return 1
	}
	if len(leftPre) < len(rightPre) {
		return -1
	}
	if len(leftPre) > len(rightPre) {
		return 1
	}
	return 0
}
