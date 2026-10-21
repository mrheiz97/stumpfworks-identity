package passkey

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

const maximumSessionBytes = 64 << 10

type Adapter struct {
	rpID   string
	origin string
	inner  *wa.WebAuthn
}

func New(rpID, origin string) (*Adapter, error) {
	rpID = strings.TrimSpace(strings.ToLower(rpID))
	parsed, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Passkey origin must be an exact HTTPS origin")
	}
	if rpID == "" || strings.ContainsAny(rpID, ":/") || !strings.EqualFold(parsed.Hostname(), rpID) {
		return nil, errors.New("Passkey RP ID must exactly match the origin hostname")
	}
	origin = "https://" + parsed.Host
	inner, err := wa.New(&wa.Config{
		RPID:                  rpID,
		RPDisplayName:         "StumpfWorks Identity",
		RPOrigins:             []string{origin},
		RPAllowCrossOrigin:    false,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: wa.TimeoutsConfig{
			Login:        wa.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute},
			Registration: wa.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Adapter{rpID: rpID, origin: origin, inner: inner}, nil
}

func (a *Adapter) RPID() string   { return a.rpID }
func (a *Adapter) Origin() string { return a.origin }

func (a *Adapter) BeginDiscoverableLogin() (*protocol.CredentialAssertion, []byte, error) {
	if a == nil || a.inner == nil {
		return nil, nil, errors.New("Passkey adapter is not configured")
	}
	options, session, err := a.inner.BeginDiscoverableLogin(
		wa.WithUserVerification(protocol.VerificationRequired),
		wa.WithLoginRelyingPartyID(a.rpID),
		wa.WithLoginOrigin(a.origin),
	)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := json.Marshal(session)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSessionBytes {
		return nil, nil, errors.New("Passkey session could not be encoded safely")
	}
	return options, encoded, nil
}

func DecodeSession(encoded []byte) (wa.SessionData, error) {
	var session wa.SessionData
	if len(encoded) == 0 || len(encoded) > maximumSessionBytes {
		return session, errors.New("invalid Passkey session size")
	}
	if err := json.Unmarshal(encoded, &session); err != nil || session.Challenge == "" || session.RelyingPartyID == "" || session.Origin == "" || session.Expires.IsZero() || session.UserVerification != protocol.VerificationRequired {
		return wa.SessionData{}, errors.New("invalid Passkey session")
	}
	return session, nil
}
