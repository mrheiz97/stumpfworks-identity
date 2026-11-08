package adprofile

import (
	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

// criticalControl deliberately has no optional/false criticality setting.
// RFC 4511 section 5.1 requires BOOLEAN TRUE to be encoded as FF, whereas
// go-ldap's pinned generic ControlString encoder uses BER TRUE=01.
// Keep this adapter local; do not alter dependencies or their global encoders.
type criticalControl struct{ oid, value string }

func newCriticalControl(oid, value string) ldap.Control { return criticalControl{oid, value} }
func (c criticalControl) GetControlType() string        { return c.oid }
func (c criticalControl) String() string                { return "LDAP critical control: " + c.oid }
func (c criticalControl) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.oid, "OID"))
	p.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	if c.value != "" {
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.value, "Value"))
	}
	return p
}
