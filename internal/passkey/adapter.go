package passkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

const maximumSessionBytes = 64 << 10
const maximumAssertionBytes = 64 << 10
const maximumRegistrationBytes = 64 << 10

type Adapter struct {
	rpID   string
	origin string
	inner  *wa.WebAuthn
}

// Credential is the stable, application-owned public credential projection
// accepted by the pinned WebAuthn adapter. Private authenticator material is
// never available to Identity.
type Credential struct {
	ID                []byte
	PublicKey         []byte
	AttestationType   string
	AttestationFormat string
	Transports        []protocol.AuthenticatorTransport
	Flags             byte
	SignCount         uint32
	BackupEligible    bool
	BackupState       bool
}

type User struct {
	LocalID     int64
	Handle      []byte
	Name        string
	DisplayName string
	Credentials []Credential
}

func (u *User) WebAuthnID() []byte          { return append([]byte(nil), u.Handle...) }
func (u *User) WebAuthnName() string        { return u.Name }
func (u *User) WebAuthnDisplayName() string { return u.DisplayName }
func (u *User) WebAuthnCredentials() []wa.Credential {
	credentials := make([]wa.Credential, 0, len(u.Credentials))
	for _, stored := range u.Credentials {
		rawFlags := protocol.AuthenticatorFlags(stored.Flags)
		if stored.BackupState {
			rawFlags |= protocol.FlagBackupState
		} else {
			rawFlags &^= protocol.FlagBackupState
		}
		flags := wa.NewCredentialFlags(rawFlags)
		credentials = append(credentials, wa.Credential{
			ID:                append([]byte(nil), stored.ID...),
			PublicKey:         append([]byte(nil), stored.PublicKey...),
			AttestationType:   stored.AttestationType,
			AttestationFormat: stored.AttestationFormat,
			Transport:         append([]protocol.AuthenticatorTransport(nil), stored.Transports...),
			Flags:             flags,
			Authenticator:     wa.Authenticator{SignCount: stored.SignCount},
		})
	}
	return credentials
}

type AuthenticationResult struct {
	LocalUserID  int64
	CredentialID []byte
	SignCount    uint32
	BackupState  bool
}

type RegistrationResult struct {
	CredentialID      []byte
	PublicKey         []byte
	AttestationType   string
	AttestationFormat string
	Transports        []protocol.AuthenticatorTransport
	Flags             byte
	SignCount         uint32
	BackupEligible    bool
	BackupState       bool
}

type DiscoverableUserLookup func(rawCredentialID, userHandle []byte) (*User, error)

func validStoredUser(user *User, requireCredential bool) bool {
	if user == nil || user.LocalID < 1 || len(user.Handle) < 32 || len(user.Handle) > 64 || user.Name == "" || len(user.Name) > 256 || len(user.DisplayName) > 256 || len(user.Credentials) > 64 || requireCredential && len(user.Credentials) < 1 {
		return false
	}
	for _, credential := range user.Credentials {
		if len(credential.ID) < 1 || len(credential.ID) > 4096 || len(credential.PublicKey) < 1 || len(credential.PublicKey) > 8192 || len(credential.AttestationType) > 64 || len(credential.AttestationFormat) > 64 || len(credential.Transports) > 16 {
			return false
		}
		flags := wa.NewCredentialFlags(protocol.AuthenticatorFlags(credential.Flags))
		if flags.BackupEligible != credential.BackupEligible || credential.BackupState && !credential.BackupEligible {
			return false
		}
		for _, transport := range credential.Transports {
			if len(transport) == 0 || len(transport) > 32 {
				return false
			}
		}
	}
	return true
}

func (a *Adapter) BeginRegistration(user *User) (*protocol.CredentialCreation, []byte, error) {
	if a == nil || a.inner == nil || !validStoredUser(user, false) {
		return nil, nil, errors.New("Passkey registration user is invalid")
	}
	options, session, err := a.inner.BeginRegistration(user,
		wa.WithExclusions(wa.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
		wa.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}),
		wa.WithConveyancePreference(protocol.PreferNoAttestation),
		wa.WithRegistrationRelyingPartyID(a.rpID),
		wa.WithRegistrationOrigin(a.origin),
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

func (a *Adapter) ValidateRegistration(user *User, encodedSession, response []byte) (RegistrationResult, error) {
	if a == nil || a.inner == nil || !validStoredUser(user, false) {
		return RegistrationResult{}, errors.New("Passkey registration user is invalid")
	}
	if len(response) == 0 || len(response) > maximumRegistrationBytes {
		return RegistrationResult{}, errors.New("invalid Passkey registration size")
	}
	session, err := DecodeSession(encodedSession)
	if err != nil || session.RelyingPartyID != a.rpID || session.Origin != a.origin || session.UserVerification != protocol.VerificationRequired || !equalBytes(session.UserID, user.Handle) {
		return RegistrationResult{}, errors.New("Passkey session boundary mismatch")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return RegistrationResult{}, errors.New("invalid Passkey registration response")
	}
	credential, err := a.inner.CreateCredential(user, session, parsed)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("Passkey registration verification failed: %w", err)
	}
	if credential == nil || len(credential.ID) == 0 || len(credential.PublicKey) == 0 {
		return RegistrationResult{}, errors.New("Passkey registration verification failed")
	}
	if credential.Authenticator.CloneWarning {
		return RegistrationResult{}, errors.New("Passkey credential counter rejected")
	}
	return RegistrationResult{
		CredentialID:      append([]byte(nil), credential.ID...),
		PublicKey:         append([]byte(nil), credential.PublicKey...),
		AttestationType:   credential.AttestationType,
		AttestationFormat: credential.AttestationFormat,
		Transports:        append([]protocol.AuthenticatorTransport(nil), credential.Transport...),
		Flags:             credential.Flags.MsgpByte(),
		SignCount:         credential.Authenticator.SignCount,
		BackupEligible:    credential.Flags.BackupEligible,
		BackupState:       credential.Flags.BackupState,
	}, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
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

func (a *Adapter) ValidateDiscoverableLogin(encodedSession, assertion []byte, lookup DiscoverableUserLookup) (AuthenticationResult, error) {
	if a == nil || a.inner == nil || lookup == nil {
		return AuthenticationResult{}, errors.New("Passkey adapter is not configured")
	}
	if len(assertion) == 0 || len(assertion) > maximumAssertionBytes {
		return AuthenticationResult{}, errors.New("invalid Passkey assertion size")
	}
	session, err := DecodeSession(encodedSession)
	if err != nil || session.RelyingPartyID != a.rpID || session.Origin != a.origin || session.UserVerification != protocol.VerificationRequired || len(session.UserID) != 0 {
		return AuthenticationResult{}, errors.New("Passkey session boundary mismatch")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		return AuthenticationResult{}, errors.New("invalid Passkey assertion")
	}
	var resolved *User
	user, verified, err := a.inner.ValidatePasskeyLogin(func(rawID, userHandle []byte) (wa.User, error) {
		candidate, lookupErr := lookup(append([]byte(nil), rawID...), append([]byte(nil), userHandle...))
		if lookupErr != nil || !validStoredUser(candidate, true) {
			return nil, errors.New("Passkey account unavailable")
		}
		resolved = candidate
		return candidate, nil
	}, session, parsed)
	if err != nil || verified == nil || user == nil || resolved == nil || user != resolved {
		return AuthenticationResult{}, errors.New("Passkey assertion verification failed")
	}
	if verified.Authenticator.CloneWarning {
		return AuthenticationResult{}, errors.New("Passkey signature counter rejected")
	}
	return AuthenticationResult{
		LocalUserID:  resolved.LocalID,
		CredentialID: append([]byte(nil), verified.ID...),
		SignCount:    verified.Authenticator.SignCount,
		BackupState:  verified.Flags.BackupState,
	}, nil
}
