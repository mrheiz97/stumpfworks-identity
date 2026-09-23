package server

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var loginUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type PKINITIssuer struct {
	cert  *x509.Certificate
	key   crypto.Signer
	caPEM string
	realm string
	life  time.Duration
}

type PKINITRequest struct {
	Grant    string `json:"grant"`
	ClientID string `json:"client_id"`
	CSR      string `json:"csr"`
}

type PKINITResponse struct {
	Username    string `json:"username"`
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	ExpiresAt   string `json:"expires_at"`
}

func LoadPKINITIssuer(certFile, keyFile, realm string, life time.Duration) (*PKINITIssuer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("invalid PKINIT CA PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(kb.Bytes); err != nil {
		if key, err = x509.ParsePKCS1PrivateKey(kb.Bytes); err != nil {
			return nil, err
		}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("PKINIT CA key is not a signer")
	}
	if !cert.IsCA {
		return nil, errors.New("PKINIT issuer certificate is not a CA")
	}
	if life <= 0 || life > 15*time.Minute {
		return nil, errors.New("PKINIT certificate lifetime must be between 1ns and 15m")
	}
	return &PKINITIssuer{cert: cert, key: signer, caPEM: string(certPEM), realm: strings.ToUpper(realm), life: life}, nil
}

func (s *Server) ConfigurePKINIT(i *PKINITIssuer) { s.pkinit = i }

func (s *Server) issuePKINIT(w http.ResponseWriter, r *http.Request) {
	if s.pkinit == nil {
		s.problem(w, 503, "pkinit_disabled")
		return
	}
	var in PKINITRequest
	if decode(w, r, &in) != nil || in.Grant == "" || in.ClientID == "" || len(in.CSR) > 16384 {
		s.problem(w, 400, "invalid_request")
		return
	}
	g, ok := s.redeemLoginGrant(in.Grant, in.ClientID)
	if !ok || !loginUsername.MatchString(g.Username) {
		s.audit(r.Context(), "pkinit_denied", "", "", in.ClientID, false, remoteIP(r), "invalid_grant")
		s.problem(w, 403, "invalid_grant")
		return
	}
	block, _ := pem.Decode([]byte(in.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		s.problem(w, 400, "invalid_csr")
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		s.problem(w, 400, "invalid_csr")
		return
	}
	certPEM, expires, err := s.pkinit.sign(g.Username, csr)
	if err != nil {
		s.log.Error("PKINIT certificate issuance failed", "error", err)
		s.problem(w, 500, "pkinit_error")
		return
	}
	s.audit(r.Context(), "pkinit_issued", "", g.Username, in.ClientID, true, remoteIP(r), "expires="+expires.UTC().Format(time.RFC3339))
	s.json(w, 200, PKINITResponse{Username: g.Username, Certificate: certPEM, CA: s.pkinit.caPEM, ExpiresAt: expires.UTC().Format(time.RFC3339)})
}

func (i *PKINITIssuer) sign(username string, csr *x509.CertificateRequest) (string, time.Time, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 159)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expires := now.Add(i.life)
	san, err := upnSAN(username + "@" + strings.ToLower(i.realm))
	if err != nil {
		return "", time.Time{}, err
	}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 2, 3, 4}, {1, 3, 6, 1, 4, 1, 311, 20, 2, 2}})
	if err != nil {
		return "", time.Time{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{Organization: []string{"StumpfWorks"}, OrganizationalUnit: []string{"Badge Login"}, CommonName: username},
		NotBefore: now.Add(-30 * time.Second), NotAfter: expires, BasicConstraintsValid: true,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{san, {Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.cert, csr.PublicKey, i.key)
	if err != nil {
		return "", time.Time{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), expires, nil
}

func upnSAN(upn string) (pkix.Extension, error) {
	type anotherName struct {
		TypeID asn1.ObjectIdentifier
		Value  string `asn1:"utf8,explicit,tag:0"`
	}
	anDER, err := asn1.Marshal(anotherName{TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, Value: upn})
	if err != nil {
		return pkix.Extension{}, err
	}
	var an asn1.RawValue
	if _, err = asn1.Unmarshal(anDER, &an); err != nil {
		return pkix.Extension{}, err
	}
	gn := asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: an.Bytes}
	value, err := asn1.Marshal([]asn1.RawValue{gn})
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}, err
}
