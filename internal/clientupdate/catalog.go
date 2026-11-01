package clientupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

type ApprovedRelease struct {
	ID                  string   `json:"id"`
	SHA256              string   `json:"sha256"`
	Manifest            Manifest `json:"manifest"`
	RequiresMaintenance bool     `json:"requires_maintenance"`
	Package             []byte   `json:"-"`
}
type Catalog map[string]ApprovedRelease

// LoadCatalog accepts only locally approved stable artifacts. Public keys and
// packages are never accepted from a browser. Bytes are frozen at startup so
// replacement of a filesystem package cannot alter an existing approval.
func LoadCatalog(directory, keyFile string) (Catalog, error) {
	key, err := LoadPublicKey(keyFile)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(directory, "approved.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var approved []struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if d.Decode(&approved) != nil || d.Decode(&struct{}{}) != io.EOF || len(approved) > 16 {
		return nil, errors.New("invalid release approvals")
	}
	catalog := Catalog{}
	var total int64
	for _, a := range approved {
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]{16,64}$`).MatchString(a.ID) || catalog[a.ID].ID != "" || len(a.SHA256) != 64 {
			return nil, errors.New("invalid release approval")
		}
		path := filepath.Join(directory, a.ID+".zip")
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() > maxPackageSize+(1<<20) {
			return nil, errors.New("invalid approved package")
		}
		file, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(io.LimitReader(file, maxPackageSize+(1<<20)+1))
		closeErr := file.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return nil, e
		}
		total += int64(len(data))
		if total > 512<<20 {
			return nil, errors.New("catalog exceeds size limit")
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		if digest != a.SHA256 {
			return nil, errors.New("approved package digest mismatch")
		}
		result, e := VerifyPackageBytes(data, key, "linux-amd64", "")
		if e != nil || result.Manifest.Channel != "stable" || len(result.Manifest.ReleaseVersion) > 64 {
			return nil, errors.New("frozen package verification failed")
		}
		maintenance := false
		for _, f := range result.Manifest.Files {
			maintenance = maintenance || componentSpecs[f.Component].RestartLightDM
		}
		catalog[a.ID] = ApprovedRelease{ID: a.ID, SHA256: digest, Manifest: result.Manifest, RequiresMaintenance: maintenance, Package: data}
	}
	return catalog, nil
}
