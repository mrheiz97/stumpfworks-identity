package deviceauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"github.com/mrheiz97/stumpfworks-framework/security/certificates"
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
	// Preserve defensive rejection of malformed parsed URI values. The framework
	// derives public metadata from signed DER, not mutable parsed fields.
	if state != nil && len(state.PeerCertificates) != 0 && state.PeerCertificates[0] != nil {
		for _, uri := range state.PeerCertificates[0].URIs {
			if uri == nil {
				return Identity{}, ErrInvalidCertificate
			}
		}
	}
	metadata, err := certificates.VerifiedPeer(state, certificates.PeerOptions{Now: now, Usage: x509.ExtKeyUsageClientAuth})
	if err != nil {
		return Identity{}, ErrInvalidCertificate
	}
	if len(metadata.URIs) != 1 || len(metadata.DNSNames) != 0 || len(metadata.EmailAddresses) != 0 || len(metadata.IPAddresses) != 0 {
		return Identity{}, ErrInvalidCertificate
	}
	uri := metadata.URIs[0]
	clientID := strings.TrimPrefix(uri, clientURIPrefix)
	if clientID == uri || !validClientID(clientID) || uri != clientURIPrefix+clientID {
		return Identity{}, ErrInvalidCertificate
	}
	return Identity{ClientID: clientID, FingerprintSHA256: metadata.FingerprintSHA256, Serial: metadata.Serial, URISAN: uri}, nil
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
