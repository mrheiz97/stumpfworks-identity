package clientupdate

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type PackageOptions struct {
	ReleaseVersion string
	Channel        string
	Architecture   string
	MinimumVersion string
	CreatedAt      time.Time
	Components     map[string]string
}

func GenerateSigningKey(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" || filepath.Clean(privatePath) == filepath.Clean(publicPath) {
		return errors.New("distinct private and public key paths are required")
	}
	if _, err := os.Lstat(privatePath); !os.IsNotExist(err) {
		return errors.New("private key path already exists")
	}
	if _, err := os.Lstat(publicPath); !os.IsNotExist(err) {
		return errors.New("public key path already exists")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err = writeExclusive(privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)), 0600); err != nil {
		return err
	}
	if err = writeExclusive(publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)), 0644); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func CreateSignedPackage(outputPath string, privateKey ed25519.PrivateKey, options PackageOptions) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}
	if outputPath == "" {
		return errors.New("output path is required")
	}
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		return errors.New("output package already exists")
	}
	if options.CreatedAt.IsZero() {
		options.CreatedAt = time.Now().UTC()
	}
	manifest := Manifest{SchemaVersion: 1, ReleaseVersion: options.ReleaseVersion, Channel: options.Channel, Architecture: options.Architecture, MinimumVersion: options.MinimumVersion, CreatedAt: options.CreatedAt.UTC()}
	names := make([]string, 0, len(options.Components))
	for name := range options.Components {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := options.Components[name]
		if !allowedComponents[name] {
			return fmt.Errorf("invalid component %q", name)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > maxFileSize {
			return fmt.Errorf("component %s is not a supported regular file", name)
		}
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, File{Component: name, Size: info.Size(), SHA256: digest})
	}
	if err := validateManifest(manifest, options.Architecture, ""); err != nil {
		return err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.Remove(outputPath)
		}
	}()
	archive := zip.NewWriter(output)
	entries := map[string][]byte{"manifest.json": manifestBytes, "manifest.sig": []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestBytes)))}
	for name, data := range entries {
		writer, createErr := archive.Create(name)
		if createErr != nil {
			_ = archive.Close()
			_ = output.Close()
			return createErr
		}
		if _, createErr = writer.Write(data); createErr != nil {
			_ = archive.Close()
			_ = output.Close()
			return createErr
		}
	}
	for _, name := range names {
		writer, createErr := archive.Create("payload/" + name)
		if createErr != nil {
			_ = archive.Close()
			_ = output.Close()
			return createErr
		}
		input, openErr := os.Open(options.Components[name])
		if openErr != nil {
			_ = archive.Close()
			_ = output.Close()
			return openErr
		}
		_, copyErr := io.Copy(writer, input)
		closeErr := input.Close()
		if copyErr != nil {
			_ = archive.Close()
			_ = output.Close()
			return copyErr
		}
		if closeErr != nil {
			_ = archive.Close()
			_ = output.Close()
			return closeErr
		}
	}
	if err = archive.Close(); err != nil {
		_ = output.Close()
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	failed = false
	return nil
}

func hashFile(path string) (string, error) {
	input, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer input.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(input, maxFileSize+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return os.Chmod(path, mode)
}
