// Package adprofile implements the opt-in, single-object stage-1 AD editor.
// It is independent of the web process and never accepts arbitrary LDAP writes.
package adprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
)

var ErrDenied = errors.New("profile operation denied")
var ErrUncertain = errors.New("profile result requires reconciliation")
var guidPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var revisionPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
var domainSIDPattern = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+$`)

type Values map[string][]string
type Snapshot struct {
	GUID, SID, DN, Version, DC string
	Values                     Values
}
type Plan struct {
	ID, Actor, Target, Policy, Digest string
	Before, After                     Snapshot
	Expires                           int64
	Parent                            string
}
type Operation struct {
	ID      string `json:"id"`
	Actor   string `json:"actor"`
	Target  string `json:"target"`
	State   string `json:"state"`
	Expires int64  `json:"expires"`
	Parent  string `json:"parent,omitempty"`
}
type Config struct {
	Enabled                                                   bool
	URL, BaseDN, ManagedOU, DomainGUID, DomainSID, DCIdentity string
	WriterDN, PasswordFile, CAFile, OperatorGroupDN, Revision string
	OperatorGroupGUID                                         string
	// Explicitly enrolled target GUIDs keep stage 1 bounded even within the OU.
	Targets        []string
	ProtectedGUIDs []string
}

func (c Config) Validate() error {
	if !guidPattern.MatchString(c.OperatorGroupGUID) || !guidPattern.MatchString(c.DCIdentity) || !domainSIDPattern.MatchString(c.DomainSID) || !revisionPattern.MatchString(c.Revision) {
		return ErrDenied
	}
	u, err := ldap.ParseDN(c.ManagedOU)
	b, e := ldap.ParseDN(c.BaseDN)
	if !c.Enabled || err != nil || e != nil || !b.AncestorOfFold(u) || !guidPattern.MatchString(c.DomainGUID) || c.DomainSID == "" || c.DCIdentity == "" || c.WriterDN == "" || c.PasswordFile == "" || c.CAFile == "" || c.OperatorGroupDN == "" || c.Revision == "" || len(c.Targets) == 0 || len(c.Targets) > 100 {
		return ErrDenied
	}
	for _, g := range append(append([]string{}, c.Targets...), c.ProtectedGUIDs...) {
		if !guidPattern.MatchString(g) {
			return ErrDenied
		}
	}
	return nil
}

func validateValues(v Values) error {
	if len(v) == 0 || len(v) > 4 {
		return ErrDenied
	}
	for attr, values := range v {
		max := 256
		switch attr {
		case "displayName":
			max = 256
		case "givenName", "sn":
			max = 64
		case "mail":
			max = 254
		default:
			return ErrDenied
		}
		if len(values) > 1 {
			return ErrDenied
		}
		if len(values) == 1 {
			s := values[0]
			if s == "" || !utf8.ValidString(s) || len(s) > max || strings.TrimSpace(s) != s {
				return ErrDenied
			}
			for _, r := range s {
				if unicode.IsControl(r) {
					return ErrDenied
				}
			}
			if attr == "mail" && (strings.Count(s, "@") != 1 || strings.ContainsAny(s, " <>\"\\")) {
				return ErrDenied
			}
		}
	}
	return nil
}

func directChild(dn, ou string) bool {
	d, e := ldap.ParseDN(dn)
	p, f := ldap.ParseDN(ou)
	return e == nil && f == nil && len(d.RDNs) == len(p.RDNs)+1 && (&ldap.DN{RDNs: d.RDNs[1:]}).EqualFold(p)
}

func digest(p Plan) string {
	p.Digest = ""
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
