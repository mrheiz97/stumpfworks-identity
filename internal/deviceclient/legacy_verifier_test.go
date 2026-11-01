package deviceclient

// Frozen pre-migration verifier, test-only. Never used as a runtime fallback.
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

func legacyValidateMaterialAt(response certificateResponse, clientID string, key *ecdsa.PrivateKey, expectedCAPEM []byte, now time.Time) (Material, error) {
	if now.IsZero() || key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || key.D == nil {
		return Material{}, errors.New("invalid device material validation context")
	}
	certificateBlock, certificateRest := pem.Decode([]byte(response.Certificate))
	caBlock, caRest := pem.Decode([]byte(response.CA))
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(certificateRest)) != 0 || caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(caRest)) != 0 {
		return Material{}, errors.New("device certificate response contains invalid PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return Material{}, err
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA {
		return Material{}, errors.New("device CA response is invalid")
	}
	if len(expectedCAPEM) != 0 {
		expectedBlock, rest := pem.Decode(expectedCAPEM)
		if expectedBlock == nil || expectedBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || subtle.ConstantTimeCompare(expectedBlock.Bytes, ca.Raw) != 1 {
			return Material{}, errors.New("renewal device CA does not match pinned CA")
		}
	}
	issuedKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || issuedKey.Curve != elliptic.P256() || issuedKey.X.Cmp(key.X) != 0 || issuedKey.Y.Cmp(key.Y) != 0 || len(certificate.URIs) != 1 || certificate.URIs[0].String() != clientURIPrefix+clientID || len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		return Material{}, errors.New("device certificate identity or key does not match")
	}
	clientAuth := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return Material{}, errors.New("device certificate is missing client authentication usage")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		return Material{}, errors.New("device certificate verification failed")
	}
	expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt)
	if err != nil || !expiresAt.Equal(certificate.NotAfter) {
		return Material{}, errors.New("device certificate expiry does not match")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Material{}, err
	}
	return Material{CertificatePEM: pem.EncodeToMemory(certificateBlock), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), CAPEM: pem.EncodeToMemory(caBlock), ExpiresAt: expiresAt.UTC()}, nil
}
