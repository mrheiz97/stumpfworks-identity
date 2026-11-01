package deviceauth

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/testutil/certificatecontract"
)

func TestFrameworkPeerPolicyUsesSignedIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	certificate := syntheticClientCertificate(t, now, []string{"urn:example:foreign:device"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	// A mutated parsed projection must not authorize an identity absent from DER.
	certificate.URIs = []*url.URL{{Scheme: "urn", Opaque: "stumpfworks:identity:client:contract-device"}}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	if identity, err := FromTLS(state, now); err != ErrInvalidCertificate || identity != (Identity{}) {
		t.Fatal("unsigned parsed identity authorized")
	}
}

func TestFrameworkExtractionPeerContract(t *testing.T) {
	certificatecontract.RunPeer(t, func(state *tls.ConnectionState, now time.Time) (certificatecontract.Peer, error) {
		identity, err := FromTLS(state, now)
		legacy, legacyErr := legacyFromTLS(state, now)
		if (err == nil) != (legacyErr == nil) || identity != legacy {
			t.Fatal("framework peer migration changed the Identity contract")
		}
		return certificatecontract.Peer{URI: identity.URISAN, FingerprintSHA256: identity.FingerprintSHA256, Serial: identity.Serial}, err
	}, "urn:stumpfworks:identity:client:contract-device")
}
