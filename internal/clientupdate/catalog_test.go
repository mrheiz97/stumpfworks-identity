package clientupdate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestApprovedCatalogBindsSignatureChannelDigestAndFrozenBytes(t *testing.T) {
	for _, channel := range []string{"stable", "development"} {
		t.Run(channel, func(t *testing.T) {
			p, key := testPackage(t, []byte("approved payload"), func(m *Manifest, b *[]byte) { m.Channel = channel; *b, _ = json.Marshal(m) }, "")
			dir := t.TempDir()
			raw, _ := os.ReadFile(p)
			sum := sha256.Sum256(raw)
			id := "approved-release-0001"
			artifact := filepath.Join(dir, id+".zip")
			os.WriteFile(artifact, raw, 0600)
			public := filepath.Join(dir, "stable.pub")
			os.WriteFile(public, []byte(base64.StdEncoding.EncodeToString(key)), 0644)
			approval, _ := json.Marshal([]map[string]string{{"id": id, "sha256": hex.EncodeToString(sum[:])}})
			os.WriteFile(filepath.Join(dir, "approved.json"), approval, 0600)
			catalog, e := LoadCatalog(dir, public)
			if channel != "stable" {
				if e == nil {
					t.Fatal("development release accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			os.WriteFile(artifact, []byte("tampered"), 0600)
			if string(catalog[id].Package) != string(raw) {
				t.Fatal("frozen artifact changed")
			}
			if _, e = LoadCatalog(dir, public); e == nil {
				t.Fatal("tampered catalog accepted")
			}
		})
	}
}
