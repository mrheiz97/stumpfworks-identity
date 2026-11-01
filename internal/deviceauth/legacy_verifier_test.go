package deviceauth

// Frozen pre-migration verifier, test-only. Never used as a runtime fallback.
import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
)

func legacyFromTLS(state *tls.ConnectionState, now time.Time) (Identity, error) {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || now.IsZero() {
		return Identity{}, ErrInvalidCertificate
	}
	certificate := state.PeerCertificates[0]
	if certificate == nil || state.VerifiedChains[0][0] == nil {
		return Identity{}, ErrInvalidCertificate
	}
	if !certificate.Equal(state.VerifiedChains[0][0]) || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 {
		return Identity{}, ErrInvalidCertificate
	}
	clientAuth := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth || len(certificate.URIs) != 1 || certificate.URIs[0] == nil || len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		return Identity{}, ErrInvalidCertificate
	}
	uri := certificate.URIs[0].String()
	clientID := strings.TrimPrefix(uri, clientURIPrefix)
	if clientID == uri || !validClientID(clientID) || uri != clientURIPrefix+clientID {
		return Identity{}, ErrInvalidCertificate
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	return Identity{ClientID: clientID, FingerprintSHA256: hex.EncodeToString(fingerprint[:]), Serial: strings.ToLower(certificate.SerialNumber.Text(16)), URISAN: uri}, nil
}
