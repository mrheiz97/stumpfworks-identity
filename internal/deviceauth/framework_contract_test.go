package deviceauth

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/testutil/certificatecontract"
)

func TestFrameworkExtractionPeerContract(t *testing.T) {
	certificatecontract.RunPeer(t, func(state *tls.ConnectionState, now time.Time) (certificatecontract.Peer, error) {
		identity, err := FromTLS(state, now)
		return certificatecontract.Peer{URI: identity.URISAN, FingerprintSHA256: identity.FingerprintSHA256, Serial: identity.Serial}, err
	}, "urn:stumpfworks:identity:client:contract-device")
}
