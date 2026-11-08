package adprofile

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

func TestCriticalControlExactWireEncoding(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"absent-value", "", "300a0405312e322e330101ff"},
		{"binary-value", "\x00\xffA", "300f0405312e322e330101ff040300ff41"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCriticalControl("1.2.3", tc.value)
			if got := hex.EncodeToString(c.Encode().Bytes()); got != tc.want {
				t.Fatalf("wire encoding: %s", got)
			}
			p, e := ber.DecodePacketErr(c.Encode().Bytes())
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(p.Children[1].Data.Bytes(), []byte{0xff}) {
				t.Fatal("criticality did not survive serialization")
			}
			if c.GetControlType() != "1.2.3" {
				t.Fatal("OID changed")
			}
		})
	}
	c := newCriticalControl(assertionOID, "sensitive-filter-marker")
	if strings.Contains(c.String(), "sensitive-filter-marker") {
		t.Fatal("diagnostic string exposed control value")
	}
	// Definite BER lengths must remain correct across the short/long boundary.
	payload := strings.Repeat("x", 256)
	p, e := ber.DecodePacketErr(newCriticalControl(assertionOID, payload).Encode().Bytes())
	if e != nil || string(p.Children[2].Data.Bytes()) != payload {
		t.Fatal("long control value changed")
	}
}

// Capture SDK request envelopes, not just the encoder's in-memory packet tree.
// The in-process pipe has no credentials, sockets to external systems or TLS bypass.
func TestCriticalControlInSDKSearchAndModify(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	server.SetDeadline(time.Now().Add(5 * time.Second))
	c := ldap.NewConn(client, false)
	c.Start()
	defer c.Close()
	c.SetTimeout(3 * time.Second)
	frames := make(chan *ber.Packet, 2)
	serverDone := make(chan error, 1)
	go func() {
		defer close(frames)
		for i := 0; i < 2; i++ {
			p, e := ber.ReadPacket(server)
			if e != nil {
				serverDone <- e
				return
			}
			frames <- p
			tag := ldap.ApplicationSearchResultDone
			if p.Children[1].Tag == ldap.ApplicationModifyRequest {
				tag = ldap.ApplicationModifyResponse
			}
			response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.Children[0].Value, ""))
			result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(tag), nil, "")
			result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
			result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
			result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
			response.AppendChild(result)
			if _, e = server.Write(response.Bytes()); e != nil {
				serverDone <- e
				return
			}
		}
		serverDone <- nil
	}()
	if _, e := search(c, "DC=example,DC=test", ldap.ScopeWholeSubtree, "(objectClass=user)", []string{"objectGUID"}); e != nil {
		t.Fatal(e)
	}
	filter, e := ldap.CompileFilter("(uSNChanged=123)")
	if e != nil {
		t.Fatal(e)
	}
	req := ldap.NewModifyRequest("CN=synthetic,DC=example,DC=test", []ldap.Control{newCriticalControl(assertionOID, string(filter.Bytes()))})
	req.Replace("displayName", []string{"Synthetic"})
	if e = c.Modify(req); e != nil {
		t.Fatal(e)
	}
	if e = <-serverDone; e != nil {
		t.Fatal(e)
	}
	i := 0
	for frame := range frames {
		if len(frame.Children) != 3 || len(frame.Children[2].Children) != 1 {
			t.Fatal("missing SDK controls envelope")
		}
		control := frame.Children[2].Children[0]
		if len(control.Children) < 2 || !bytes.Equal(control.Children[1].Bytes(), []byte{1, 1, 255}) {
			t.Fatal("SDK did not send LDAP FF criticality")
		}
		oid := string(control.Children[0].Data.Bytes())
		if i == 0 && (oid != "1.2.840.113556.1.4.1339" || len(control.Children) != 2) {
			t.Fatal("domain-scope control changed")
		}
		if i == 1 && (oid != assertionOID || len(control.Children) != 3 || !bytes.Equal(control.Children[2].Data.Bytes(), filter.Bytes())) {
			t.Fatal("assertion OID or BER filter changed")
		}
		i++
	}
	if i != 2 {
		t.Fatal("missing wire request")
	}
}
