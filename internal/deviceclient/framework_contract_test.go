package deviceclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/testutil/certificatecontract"
)

func TestFrameworkMaterialRejectsZeroSerial(t *testing.T) {
	ca, caKey, caPEM := syntheticCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(0), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{{Scheme: "urn", Opaque: "stumpfworks:identity:client:contract-device"}}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	response := certificateResponse{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CA: string(caPEM), ExpiresAt: leaf.NotAfter.Format(time.RFC3339)}
	// This intentionally tightens the former material-only check. Identity's
	// issuer, peer authorization and store already require positive serials.
	if _, err := legacyValidateMaterialAt(response, "contract-device", key, caPEM, now); err != nil {
		t.Fatal("fixture no longer characterizes the former acceptance")
	}
	if material, err := validateMaterialAt(response, "contract-device", key, caPEM, now); err == nil || !reflect.DeepEqual(material, Material{}) {
		t.Fatal("zero-serial material accepted or partially returned")
	}
}

func TestFrameworkExtractionIssuedMaterialContract(t *testing.T) {
	certificatecontract.RunIssued(t, func(v certificatecontract.IssuedInput, now time.Time) error {
		response := certificateResponse{Certificate: string(v.CertificatePEM), CA: string(v.CAPEM), ExpiresAt: v.ExpiresAt.Format(time.RFC3339)}
		material, err := validateMaterialAt(response, "contract-device", v.Key, v.PinnedCAPEM, now)
		legacy, legacyErr := legacyValidateMaterialAt(response, "contract-device", v.Key, v.PinnedCAPEM, now)
		if (err == nil) != (legacyErr == nil) || !reflect.DeepEqual(material, legacy) {
			t.Fatal("framework material migration changed the Identity contract")
		}
		return err
	}, "urn:stumpfworks:identity:client:contract-device")
}
