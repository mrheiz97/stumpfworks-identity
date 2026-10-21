package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/badge"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	passkeyauth "github.com/TheRealHZL/stumpfworks-identity/internal/passkey"
	"github.com/go-webauthn/webauthn/protocol"
)

func (s *Server) ConfigurePasskeys(adapter *passkeyauth.Adapter) error {
	if adapter == nil || !s.protect || s.dir == nil || s.sessions == nil {
		return errors.New("Passkeys require protected directory self-service")
	}
	if s.passkeys != nil {
		return errors.New("Passkeys already configured")
	}
	s.passkeys = adapter
	s.mux.HandleFunc("POST /self-service/passkeys/registration/begin", s.passkeyRegistrationBegin)
	s.mux.HandleFunc("POST /self-service/passkeys/registration/complete", s.passkeyRegistrationComplete)
	s.mux.HandleFunc("POST /self-service/passkeys/login/begin", s.passkeyLoginBegin)
	s.mux.HandleFunc("POST /self-service/passkeys/login/complete", s.passkeyLoginComplete)
	return nil
}

func (s *Server) passkeyRegistrationBegin(w http.ResponseWriter, r *http.Request) {
	username, _, token, ok := s.selfServiceSession(r)
	if !ok || !s.sessions.VerifyCSRF(token, r.Header.Get("X-CSRF-Token")) {
		s.problem(w, http.StatusForbidden, "authentication_required")
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if decode(w, r, &request) != nil || request.Password == "" {
		s.problem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ip := remoteIP(r)
	if !s.loginAllowed("passkey-registration:" + ip) {
		s.problem(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	directoryUser, err := s.dir.AuthenticateUser(r.Context(), username, request.Password)
	request.Password = ""
	if err != nil || !strings.EqualFold(directoryUser.Username, username) {
		s.loginFailed("passkey-registration:" + ip)
		s.audit(r.Context(), "passkey_registration_denied", "", username, "", false, ip, "invalid_credentials")
		s.problem(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	s.loginSucceeded("passkey-registration:" + ip)
	user, err := s.passkeyUserByUsername(r, username)
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	options, sessionData, err := s.passkeys.BeginRegistration(user)
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	id, err := badge.GenerateToken()
	now := time.Now().UTC()
	if err != nil || s.store.CreateWebAuthnCeremony(r.Context(), database.WebAuthnCeremony{ID: id, Kind: "registration", Audience: "self-service", UserID: sql.NullInt64{Int64: user.LocalID, Valid: true}, SessionData: sessionData, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}) != nil {
		s.problem(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	s.loginFailed("passkey-registration:" + ip)
	s.json(w, http.StatusOK, map[string]any{"ceremony_id": id, "publicKey": options.Response})
}

func (s *Server) passkeyRegistrationComplete(w http.ResponseWriter, r *http.Request) {
	username, _, token, ok := s.selfServiceSession(r)
	if !ok || !s.sessions.VerifyCSRF(token, r.Header.Get("X-CSRF-Token")) {
		s.problem(w, http.StatusForbidden, "authentication_required")
		return
	}
	var request struct {
		CeremonyID string          `json:"ceremony_id"`
		Name       string          `json:"name"`
		Response   json.RawMessage `json:"response"`
	}
	if decode(w, r, &request) != nil || strings.TrimSpace(request.Name) != request.Name || request.Name == "" || len(request.Name) > 64 {
		s.problem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	now := time.Now().UTC()
	ceremony, err := s.store.ActiveWebAuthnCeremony(r.Context(), request.CeremonyID, "registration", "self-service", now)
	user, userErr := s.passkeyUserByUsername(r, username)
	if err != nil || userErr != nil || !ceremony.UserID.Valid || ceremony.UserID.Int64 != user.LocalID {
		s.problem(w, http.StatusBadRequest, "registration_failed")
		return
	}
	verified, err := s.passkeys.ValidateRegistration(user, ceremony.SessionData, request.Response)
	if err != nil {
		s.problem(w, http.StatusBadRequest, "registration_failed")
		return
	}
	transports := make([]string, len(verified.Transports))
	for index, transport := range verified.Transports {
		transports[index] = string(transport)
	}
	credential := database.WebAuthnCredential{CredentialID: verified.CredentialID, UserID: user.LocalID, PublicKey: verified.PublicKey, RPID: s.passkeys.RPID(), Name: request.Name, Transports: strings.Join(transports, ","), AttestationType: verified.AttestationType, AttestationFormat: verified.AttestationFormat, Flags: int64(verified.Flags), SignCount: verified.SignCount, BackupEligible: verified.BackupEligible, BackupState: verified.BackupState}
	if err = s.store.CompleteWebAuthnRegistration(r.Context(), ceremony.ID, "self-service", now, credential, username, remoteIP(r)); err != nil {
		s.problem(w, http.StatusBadRequest, "registration_failed")
		return
	}
	s.loginSucceeded("passkey-registration:" + remoteIP(r))
	s.json(w, http.StatusOK, map[string]string{"status": "registered"})
}

func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if !s.loginAllowed("passkey-login:" + ip) {
		s.problem(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	options, sessionData, err := s.passkeys.BeginDiscoverableLogin()
	id, tokenErr := badge.GenerateToken()
	now := time.Now().UTC()
	if err != nil || tokenErr != nil || s.store.CreateWebAuthnCeremony(r.Context(), database.WebAuthnCeremony{ID: id, Kind: "authentication", Audience: "self-service", SessionData: sessionData, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}) != nil {
		s.problem(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	s.loginFailed("passkey-login:" + ip)
	s.json(w, http.StatusOK, map[string]any{"ceremony_id": id, "publicKey": options.Response})
}

func (s *Server) passkeyLoginComplete(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CeremonyID string          `json:"ceremony_id"`
		Response   json.RawMessage `json:"response"`
	}
	if decode(w, r, &request) != nil {
		s.problem(w, http.StatusBadRequest, "login_failed")
		return
	}
	ip := remoteIP(r)
	if !s.loginAllowed("passkey-login:" + ip) {
		s.problem(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	now := time.Now().UTC()
	ceremony, err := s.store.ActiveWebAuthnCeremony(r.Context(), request.CeremonyID, "authentication", "self-service", now)
	if err != nil {
		s.loginFailed("passkey-login:" + ip)
		s.problem(w, http.StatusUnauthorized, "login_failed")
		return
	}
	verified, err := s.passkeys.ValidateDiscoverableLogin(ceremony.SessionData, request.Response, func(rawID, handle []byte) (*passkeyauth.User, error) {
		return s.passkeyUserByHandle(r, rawID, handle)
	})
	if err != nil {
		s.loginFailed("passkey-login:" + ip)
		s.audit(r.Context(), "passkey_login", "", "", "", false, ip, "verification_failed")
		s.problem(w, http.StatusUnauthorized, "login_failed")
		return
	}
	user, err := s.store.GetUser(r.Context(), verified.LocalUserID)
	sessionID, tokenErr := badge.GenerateToken()
	expires := now.Add(15 * time.Minute)
	if err != nil || tokenErr != nil || s.store.CompleteWebAuthnAuthentication(r.Context(), ceremony.ID, now, database.WebAuthnAuthenticationUpdate{CredentialID: verified.CredentialID, UserID: verified.LocalUserID, SignCount: verified.SignCount, BackupState: verified.BackupState}, database.SelfServiceSession{ID: sessionID, Username: user.Username, ExpiresAt: expires}, ip) != nil {
		s.problem(w, http.StatusUnauthorized, "login_failed")
		return
	}
	s.loginSucceeded("passkey-login:" + ip)
	token := s.sessions.IssueForDuration("self-service", user.Username+"\x1f"+sessionID, now, 15*time.Minute)
	http.SetCookie(w, &http.Cookie{Name: "swbadge_selfservice", Value: token, Path: "/self-service", MaxAge: 900, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	s.json(w, http.StatusOK, map[string]string{"status": "authenticated"})
}

func (s *Server) passkeyUserByUsername(r *http.Request, username string) (*passkeyauth.User, error) {
	user, err := s.store.UserByUsername(r.Context(), username)
	if err != nil {
		return nil, err
	}
	handle, err := s.store.EnsureWebAuthnUserHandle(r.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	credentials, err := s.store.WebAuthnCredentialsByUser(r.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	return projectPasskeyUser(user, handle, credentials, s.passkeys.RPID())
}

func (s *Server) passkeyUserByHandle(r *http.Request, rawID, handle []byte) (*passkeyauth.User, error) {
	user, err := s.store.WebAuthnUserByHandle(r.Context(), handle)
	if err != nil {
		return nil, err
	}
	credentials, err := s.store.WebAuthnCredentialsByUser(r.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	projected, err := projectPasskeyUser(user, handle, credentials, s.passkeys.RPID())
	if err != nil {
		return nil, err
	}
	for _, credential := range projected.Credentials {
		if string(credential.ID) == string(rawID) {
			return projected, nil
		}
	}
	return nil, sql.ErrNoRows
}

func projectPasskeyUser(user database.User, handle []byte, credentials []database.WebAuthnCredential, rpID string) (*passkeyauth.User, error) {
	projected := &passkeyauth.User{LocalID: user.ID, Handle: append([]byte(nil), handle...), Name: user.Username, DisplayName: user.DisplayName}
	for _, credential := range credentials {
		if credential.RPID != rpID || credential.Flags < 0 || credential.Flags > 255 {
			return nil, errors.New("Passkey credential boundary mismatch")
		}
		var transports []protocol.AuthenticatorTransport
		if credential.Transports != "" {
			for _, value := range strings.Split(credential.Transports, ",") {
				transports = append(transports, protocol.AuthenticatorTransport(value))
			}
		}
		projected.Credentials = append(projected.Credentials, passkeyauth.Credential{ID: credential.CredentialID, PublicKey: credential.PublicKey, AttestationType: credential.AttestationType, AttestationFormat: credential.AttestationFormat, Transports: transports, Flags: byte(credential.Flags), SignCount: credential.SignCount, BackupEligible: credential.BackupEligible, BackupState: credential.BackupState})
	}
	return projected, nil
}
