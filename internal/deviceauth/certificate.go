package deviceauth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const clientURIPrefix = "urn:stumpfworks:identity:client:"

var ErrInvalidCertificate = errors.New("invalid client device certificate")

type Identity struct {
	ClientID          string
	FingerprintSHA256 string
	Serial            string
	URISAN            string
}

func FromTLS(state *tls.ConnectionState, now time.Time) (Identity, error) {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || now.IsZero() {
		return Identity{}, ErrInvalidCertificate
	}
	certificate := state.PeerCertificates[0]
	if !certificate.Equal(state.VerifiedChains[0][0]) || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 {
		return Identity{}, ErrInvalidCertificate
	}
	clientAuth := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth || len(certificate.URIs) != 1 || len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
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

func validClientID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
