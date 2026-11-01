package deviceclient

import (
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/testutil/certificatecontract"
)

func TestFrameworkExtractionIssuedMaterialContract(t *testing.T) {
	certificatecontract.RunIssued(t, func(v certificatecontract.IssuedInput, now time.Time) error {
		_, err := validateMaterialAt(certificateResponse{Certificate: string(v.CertificatePEM), CA: string(v.CAPEM), ExpiresAt: v.ExpiresAt.Format(time.RFC3339)}, "contract-device", v.Key, v.PinnedCAPEM, now)
		return err
	}, "urn:stumpfworks:identity:client:contract-device")
}
