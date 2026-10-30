package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/deviceauth"
)

type DeviceCertificateIssuer struct {
	certificate *x509.Certificate
	key         crypto.Signer
	caPEM       string
	issuerID    string
	lifetime    time.Duration
}

type deviceEnrollmentRequest struct {
	ClientID string `json:"client_id"`
	Token    string `json:"enrollment_token"`
	CSR      string `json:"csr"`
}

type deviceRenewalRequest struct {
	CSR string `json:"csr"`
}

type deviceCertificateResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	ExpiresAt   string `json:"expires_at"`
}

func LoadDeviceCertificateIssuer(certFile, keyFile string, lifetime time.Duration) (*DeviceCertificateIssuer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	if len(certPEM) == 0 || len(certPEM) > 1<<20 || len(keyPEM) == 0 || len(keyPEM) > 1<<20 {
		return nil, errors.New("device CA files must contain at most 1 MiB")
	}
	certificateBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || keyBlock == nil {
		return nil, errors.New("invalid device CA PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, err
	}
	var parsedKey any
	if parsedKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		if parsedKey, err = x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
			if parsedKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
				return nil, errors.New("invalid device CA private key")
			}
		}
	}
	signer, ok := parsedKey.(crypto.Signer)
	now := time.Now().UTC()
	if !ok || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || !certificate.NotAfter.After(now.Add(24*time.Hour)) || lifetime < 24*time.Hour || lifetime > 397*24*time.Hour {
		return nil, errors.New("invalid device CA issuer")
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || subtle.ConstantTimeCompare(certificatePublic, keyPublic) != 1 {
		return nil, errors.New("device CA certificate and key do not match")
	}
	issuerHash := sha256.Sum256(certificate.Raw)
	return &DeviceCertificateIssuer{certificate: certificate, key: signer, caPEM: string(pem.EncodeToMemory(certificateBlock)), issuerID: hex.EncodeToString(issuerHash[:]), lifetime: lifetime}, nil
}

func (s *Server) ConfigureDeviceCertificateIssuer(issuer *DeviceCertificateIssuer) {
	s.deviceIssuer = issuer
}

func (s *Server) ClientAPIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/client/status", s.clientStatus)
	mux.HandleFunc("POST /api/v1/client/renew", s.renewClientDeviceCertificate)
	mux.HandleFunc("POST /api/v1/client/activate", s.activateClientDeviceCertificate)
	return s.security(mux)
}

func (s *Server) ClientEnrollmentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/client/enroll", s.enrollClientDeviceCertificate)
	return s.security(mux)
}

func (s *Server) enrollClientDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	if s.deviceIssuer == nil {
		s.problem(w, http.StatusNotFound, "not_found")
		return
	}
	var request deviceEnrollmentRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 24<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || !validClientID(request.ClientID) || len(request.Token) < 32 || len(request.Token) > 256 || len(request.CSR) > 16<<10 {
		s.problem(w, http.StatusBadRequest, "invalid_device_enrollment")
		return
	}
	csr, err := parseDeviceCSR(request.CSR)
	if err != nil {
		s.problem(w, http.StatusBadRequest, "invalid_device_enrollment")
		return
	}
	now := time.Now().UTC()
	tokenHash := sha256.Sum256([]byte(request.Token))
	encodedTokenHash := hex.EncodeToString(tokenHash[:])
	valid, err := s.store.ValidClientEnrollmentToken(r.Context(), request.ClientID, encodedTokenHash, now)
	if err != nil || !valid {
		s.problem(w, http.StatusUnauthorized, "invalid_device_enrollment")
		return
	}
	certificatePEM, credential, err := s.deviceIssuer.issue(request.ClientID, csr, now)
	if err != nil {
		s.problem(w, http.StatusInternalServerError, "device_enrollment_failed")
		return
	}
	if err = s.store.EnrollClientDeviceCredentialWithAudit(r.Context(), encodedTokenHash, now, credential, remoteIP(r)); err != nil {
		s.problem(w, http.StatusUnauthorized, "invalid_device_enrollment")
		return
	}
	s.json(w, http.StatusOK, deviceCertificateResponse{Certificate: certificatePEM, CA: s.deviceIssuer.caPEM, ExpiresAt: credential.ExpiresAt.UTC().Format(time.RFC3339)})
}

func (s *Server) renewClientDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	if s.deviceIssuer == nil {
		s.problem(w, http.StatusNotFound, "not_found")
		return
	}
	identity, err := deviceauth.FromTLS(r.TLS, time.Now().UTC())
	if err != nil {
		s.problem(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}
	current, err := s.store.ActiveClientDeviceCredential(r.Context(), identity.ClientID, time.Now().UTC())
	if err != nil || !sameDeviceCredential(identity, current) {
		s.problem(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}
	var request deviceRenewalRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 20<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || len(request.CSR) > 16<<10 {
		s.problem(w, http.StatusBadRequest, "invalid_device_renewal")
		return
	}
	csr, err := parseDeviceCSR(request.CSR)
	if err != nil {
		s.problem(w, http.StatusBadRequest, "invalid_device_renewal")
		return
	}
	certificatePEM, replacement, err := s.deviceIssuer.issue(identity.ClientID, csr, time.Now().UTC())
	if err != nil {
		s.problem(w, http.StatusInternalServerError, "device_renewal_failed")
		return
	}
	if err = s.store.StageClientDeviceCredentialRenewalWithAudit(r.Context(), current.ID, time.Now().UTC(), replacement, remoteIP(r)); err != nil {
		s.problem(w, http.StatusConflict, "device_renewal_failed")
		return
	}
	s.json(w, http.StatusOK, deviceCertificateResponse{Certificate: certificatePEM, CA: s.deviceIssuer.caPEM, ExpiresAt: replacement.ExpiresAt.UTC().Format(time.RFC3339)})
}

func (s *Server) activateClientDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	identity, err := deviceauth.FromTLS(r.TLS, now)
	if err != nil {
		s.problem(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}
	pending, err := s.store.PendingClientDeviceCredential(r.Context(), identity.ClientID, now)
	if err != nil || !sameDeviceCredential(identity, pending) {
		s.problem(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}
	client, err := s.store.ClientByID(r.Context(), identity.ClientID)
	if err != nil || !client.Enabled {
		s.problem(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}
	if err = s.store.ActivateClientDeviceCredentialWithAudit(r.Context(), identity.ClientID, pending.ID, remoteIP(r), now); err != nil {
		s.problem(w, http.StatusConflict, "device_activation_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseDeviceCSR(value string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("invalid CSR signature")
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("device key must use ECDSA P-256")
	}
	return csr, nil
}

func (issuer *DeviceCertificateIssuer) issue(clientID string, csr *x509.CertificateRequest, now time.Time) (string, database.ClientDeviceCredential, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil || serial.Sign() == 0 {
		return "", database.ClientDeviceCredential{}, errors.New("device serial generation failed")
	}
	credentialBytes := make([]byte, 16)
	if _, err = rand.Read(credentialBytes); err != nil {
		return "", database.ClientDeviceCredential{}, err
	}
	identityURI, err := url.Parse("urn:stumpfworks:identity:client:" + clientID)
	if err != nil {
		return "", database.ClientDeviceCredential{}, err
	}
	expires := now.Add(issuer.lifetime)
	if expires.After(issuer.certificate.NotAfter) {
		expires = issuer.certificate.NotAfter
	}
	if !expires.After(now) {
		return "", database.ClientDeviceCredential{}, errors.New("device CA is expired")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{Organization: []string{"StumpfWorks"}, OrganizationalUnit: []string{"Managed Devices"}}, NotBefore: now.Add(-30 * time.Second), NotAfter: expires, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identityURI}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.certificate, csr.PublicKey, issuer.key)
	if err != nil {
		return "", database.ClientDeviceCredential{}, err
	}
	fingerprint := sha256.Sum256(der)
	credential := database.ClientDeviceCredential{ID: hex.EncodeToString(credentialBytes), ClientID: clientID, FingerprintSHA256: hex.EncodeToString(fingerprint[:]), Serial: serial.Text(16), URISAN: identityURI.String(), PublicKeyAlgorithm: "ECDSA-P256", IssuerID: issuer.issuerID, IssuedAt: template.NotBefore.UTC(), ExpiresAt: expires.UTC()}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), credential, nil
}

func sameDeviceCredential(identity deviceauth.Identity, credential database.ClientDeviceCredential) bool {
	got, err := hex.DecodeString(identity.FingerprintSHA256)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(credential.FingerprintSHA256)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1 && identity.Serial == credential.Serial && identity.URISAN == credential.URISAN
}
