package adprofile

// Investigation only: direct LDAP probes must NEVER become a runtime fallback.
import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

// Test-only wire probe. Generic BER Boolean TRUE=01 is not LDAP TRUE=FF.
type ldapCriticalProbe struct{ *ldap.ControlString }

func TestCASResearchCriticalityWireFormat(t *testing.T) {
	generic := ldap.NewControlString(assertionOID, true, "synthetic-filter")
	if !reflect.DeepEqual(generic.Encode().Children[1].Bytes(), []byte{1, 1, 1}) {
		t.Fatal("pinned generic encoder changed: review CAS research")
	}
	strict := ldapCriticalProbe{generic}
	if !reflect.DeepEqual(strict.Encode().Children[1].Bytes(), []byte{1, 1, 255}) {
		t.Fatal("test LDAP TRUE must be FF")
	}
	if strict.GetControlType() != assertionOID || strict.ControlValue != generic.ControlValue {
		t.Fatal("wire probe changed OID/filter")
	}
}

func (c ldapCriticalProbe) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.ControlType, "OID"))
	p.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	if c.ControlValue != "" {
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.ControlValue, "Value"))
	}
	return p
}

// Raw, bounded lab-only exchange distinguishes Samba's ExtendedResponse from
// go-ldap Modify's generic "unexpected response". Never log bind packets.
func rawCriticalProbe(d *LDAP, dn string, control ldap.Control) (uint64, error) {
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "dc1.profile.test:636", &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.roots, ServerName: "dc1.profile.test"})
	if e != nil {
		return 0, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	envelope := func(id int64, request *ber.Packet) *ber.Packet {
		p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
		p.AppendChild(request)
		return p
	}
	bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "")
	bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, ""))
	bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, d.Config.WriterDN, ""))
	bind.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, d.password, ""))
	if _, e = c.Write(envelope(1, bind).Bytes()); e != nil {
		return 0, e
	}
	reply, e := ber.ReadPacket(io.LimitReader(c, 1<<20))
	if e != nil {
		return 0, e
	}
	if e = ldap.GetLDAPError(reply); e != nil {
		return 0, e
	}
	modify := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationModifyRequest, nil, "")
	modify.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	change := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	change.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldap.ReplaceAttribute, ""))
	attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "displayName", ""))
	values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
	values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "raw-FF-must-not-write", ""))
	attr.AppendChild(values)
	change.AppendChild(attr)
	changes.AppendChild(change)
	modify.AppendChild(changes)
	request := envelope(2, modify)
	controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
	controls.AppendChild(control.Encode())
	request.AppendChild(controls)
	if _, e = c.Write(request.Bytes()); e != nil {
		return 0, e
	}
	reply, e = ber.ReadPacket(io.LimitReader(c, 1<<20))
	if e != nil || len(reply.Children) < 2 {
		return 0, ErrDenied
	}
	return uint64(reply.Children[1].Tag), ldap.GetLDAPError(reply)
}

func TestSambaCASResearch(t *testing.T) {
	path := os.Getenv("IDENTITY_AD_PROFILE_LAB")
	if path == "" {
		t.Skip("isolated Samba fixture not configured")
	}
	if path != "/tmp/lab-config.json" {
		t.Fatal("laboratory-only fixture required")
	}
	var lab struct {
		Config   Config
		Targets  map[string]string
		Password string
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &lab) != nil {
		t.Fatal("fixture unavailable")
	}
	if lab.Config.URL != "ldaps://dc1.profile.test:636" || lab.Config.BaseDN != "DC=profile,DC=test" {
		t.Fatal("synthetic domain required")
	}
	d, err := NewLDAP(lab.Config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor, err := d.Authenticate(ctx, "operator", lab.Password)
	if err != nil {
		t.Fatal("operator unavailable")
	}
	original, err := d.Read(ctx, lab.Targets["casprobe"], actor)
	if err != nil {
		t.Fatal("probe target unavailable")
	}
	c, err := d.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	read := func(t *testing.T) Snapshot {
		t.Helper()
		v, e := d.Read(ctx, original.GUID, actor)
		if e != nil {
			t.Fatal("probe read failed")
		}
		return v
	}
	replace := func(t *testing.T, attr, value string) {
		t.Helper()
		req := ldap.NewModifyRequest(original.DN, nil)
		req.Replace(attr, []string{value})
		if c.Modify(req) != nil {
			t.Fatal("fixture replacement failed")
		}
	}
	restore := func(t *testing.T) {
		t.Helper()
		req := ldap.NewModifyRequest(original.DN, nil)
		for a, v := range original.Values {
			req.Replace(a, v)
		}
		if c.Modify(req) != nil {
			t.Fatal("fixture restoration failed")
		}
		if !reflect.DeepEqual(read(t).Values, original.Values) {
			t.Fatal("fixture values not restored")
		}
	}
	defer restore(t)
	reset := func(t *testing.T) {
		t.Helper()
		restore(t)
		replace(t, "displayName", "CAS-A")
		replace(t, "givenName", "Marker0")
	}
	valueCAS := func(conn *ldap.Conn, old, next string, controls []ldap.Control) error {
		req := ldap.NewModifyRequest(original.DN, controls)
		req.Delete("displayName", []string{old})
		req.Add("displayName", []string{next})
		return conn.Modify(req)
	}

	t.Run("critical_RFC4528_probe", func(t *testing.T) {
		reset(t)
		before := read(t)
		root, e := one(c, "", ldap.ScopeBaseObject, "(objectClass=*)", []string{"supportedControl", "supportedExtension"})
		if e != nil {
			t.Fatal(e)
		}
		advertised := contains(root.GetAttributeValues("supportedControl"), assertionOID)
		filter, e := ldap.CompileFilter("(&" + guidFilter(before.GUID) + "(uSNChanged=" + ldap.EscapeFilter(before.Version) + "))")
		if e != nil {
			t.Fatal(e)
		}
		req := ldap.NewModifyRequest(before.DN, []ldap.Control{ldap.NewControlString(assertionOID, true, string(filter.Bytes()))})
		req.Replace("displayName", []string{"RFC-probe"})
		e = c.Modify(req)
		var result *ldap.Error
		if errors.As(e, &result) {
			t.Logf("critical probe LDAP result=%d", result.ResultCode)
		} else if e == nil {
			t.Log("generic 01 matching request accepted")
		} else {
			t.Log("critical probe transport error")
		}
		if advertised {
			t.Fatal("backend capability changed: explicit research review required")
		}
		if e != nil {
			t.Fatal("matching critical probe rejected")
		}
		falseFilter, err := ldap.CompileFilter("(&(objectGUID=\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00)(uSNChanged=0))")
		if err != nil {
			t.Fatal(err)
		}
		control := ldap.NewControlString(assertionOID, true, string(falseFilter.Bytes()))
		if len(control.Encode().Children) != 3 || !reflect.DeepEqual(control.Encode().Children[1].Bytes(), []byte{1, 1, 1}) {
			t.Fatal("generic control encoding changed: review required")
		}
		falseReq := ldap.NewModifyRequest(before.DN, []ldap.Control{control})
		falseReq.Replace("displayName", []string{"false-assertion-wrote"})
		falseErr := c.Modify(falseReq)
		t.Logf("false assertion accepted=%v, expected value applied=%v", falseErr == nil, reflect.DeepEqual(read(t).Values["displayName"], []string{"false-assertion-wrote"}))
		if falseErr != nil || !reflect.DeepEqual(read(t).Values["displayName"], []string{"false-assertion-wrote"}) {
			t.Fatal("generic 01 observation changed: review required")
		}
		beforeStrict := read(t)
		strict := ldapCriticalProbe{control}
		if !reflect.DeepEqual(strict.Encode().Children[1].Bytes(), []byte{1, 1, 255}) {
			t.Fatal("LDAP true encoding incorrect")
		}
		strictReq := ldap.NewModifyRequest(before.DN, []ldap.Control{strict})
		strictReq.Replace("displayName", []string{"strict-false-wrote"})
		strictErr := c.Modify(strictReq)
		if strictErr == nil {
			t.Fatal("strict false assertion accepted: review required")
		}
		var strictCode *ldap.Error
		if errors.As(strictErr, &strictCode) {
			t.Logf("FF critical false assertion result=%d", strictCode.ResultCode)
		} else {
			t.Logf("FF critical false assertion accepted=%v", strictErr == nil)
		}
		if strictErr != nil && !reflect.DeepEqual(read(t), beforeStrict) {
			t.Fatal("rejected strict request mutated object")
		}
		tag, wireErr := rawCriticalProbe(d, before.DN, strict)
		var wireCode *ldap.Error
		if errors.As(wireErr, &wireCode) {
			t.Logf("FF wire response tag=%d result=%d", tag, wireCode.ResultCode)
		} else {
			t.Logf("FF wire result success=%v", wireErr == nil)
		}
		if tag != ldap.ApplicationExtendedResponse || wireCode == nil || wireCode.ResultCode != ldap.LDAPResultUnavailableCriticalExtension || !reflect.DeepEqual(read(t), beforeStrict) {
			t.Fatal("strict wire rejection or unchanged-state contract changed")
		}
		if contains(root.GetAttributeValues("supportedExtension"), "1.3.6.1.1.21.1") || contains(root.GetAttributeValues("supportedExtension"), "1.3.6.1.1.21.3") {
			t.Fatal("transaction capability changed: review required")
		}
		t.Logf("RFC4528 advertised=false; RFC5805 start/end advertised=%v/%v", contains(root.GetAttributeValues("supportedExtension"), "1.3.6.1.1.21.1"), contains(root.GetAttributeValues("supportedExtension"), "1.3.6.1.1.21.3"))
	})
	t.Run("absence_sentinel_is_not_assumed_safe", func(t *testing.T) {
		reset(t)
		before := read(t)
		req := ldap.NewModifyRequest(original.DN, nil)
		req.Add("displayName", []string{"Sentinel"})
		req.Delete("displayName", []string{"Sentinel"})
		req.Replace("givenName", []string{"absence-guard-passed"})
		e := c.Modify(req)
		t.Logf("add-delete sentinel accepts already-present attribute=%v", e == nil)
		if !ldap.IsErrorWithCode(e, ldap.LDAPResultConstraintViolation) && !ldap.IsErrorWithCode(e, ldap.LDAPResultAttributeOrValueExists) {
			t.Fatal("sentinel did not fail with a schema/value response")
		}
		if e != nil && !reflect.DeepEqual(read(t), before) {
			t.Fatal("failed sentinel probe partially committed")
		}
		if e == nil {
			t.Fatal("present-value sentinel rejection changed: review required")
		}
		empty := ldap.NewModifyRequest(original.DN, nil)
		empty.Replace("displayName", nil)
		if c.Modify(empty) != nil {
			t.Fatal("empty fixture failed")
		}
		absent := ldap.NewModifyRequest(original.DN, nil)
		absent.Add("displayName", []string{"Sentinel"})
		absent.Delete("displayName", []string{"Sentinel"})
		absent.Add("displayName", []string{"From-Absence"})
		if c.Modify(absent) != nil || read(t).Values["displayName"][0] != "From-Absence" {
			t.Fatal("absence fixture transition failed")
		}
	})
	t.Run("single_request_atomic_failure", func(t *testing.T) {
		reset(t)
		before := read(t)
		req := ldap.NewModifyRequest(original.DN, nil)
		req.Replace("givenName", []string{"must-not-commit"})
		req.Delete("displayName", []string{"wrong-old"})
		req.Add("displayName", []string{"CAS-B"})
		if e := c.Modify(req); !ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchAttribute) {
			t.Fatal("specific stale deletion not rejected")
		}
		if !reflect.DeepEqual(read(t), before) {
			t.Fatal("failed modify partially committed")
		}
	})
	t.Run("two_connections_one_value_winner", func(t *testing.T) {
		reset(t)
		other, e := d.connect(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer other.Close()
		start := make(chan struct{})
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for i, conn := range []*ldap.Conn{c, other} {
			wg.Add(1)
			go func(conn *ldap.Conn, i int) {
				defer wg.Done()
				<-start
				next := "Winner1"
				if i == 1 {
					next = "Winner2"
				}
				results <- valueCAS(conn, "CAS-A", next, nil)
			}(conn, i)
		}
		close(start)
		wg.Wait()
		close(results)
		winners := 0
		for e := range results {
			if e == nil {
				winners++
			} else if !ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchAttribute) {
				t.Fatal("unexpected race result")
			}
		}
		got := read(t).Values["displayName"]
		if winners != 1 || len(got) != 1 || (got[0] != "Winner1" && got[0] != "Winner2") {
			t.Fatal("value CAS did not have one winner")
		}
	})
	t.Run("ABA_is_not_version_CAS", func(t *testing.T) {
		reset(t)
		before := read(t)
		replace(t, "displayName", "CAS-B")
		replace(t, "displayName", "CAS-A")
		afterABA := read(t)
		if before.Version == afterABA.Version {
			t.Fatal("fixture did not advance object version")
		}
		if valueCAS(c, "CAS-A", "CAS-C", nil) != nil {
			t.Fatal("expected value-only ABA acceptance not observed")
		}
		t.Log("value CAS accepts stale A after A-B-A despite changed uSNChanged: rejected as whole-object CAS")
	})
	t.Run("unrelated_object_change_not_guarded", func(t *testing.T) {
		reset(t)
		before := read(t)
		replace(t, "sn", "External-Surname")
		if read(t).Version == before.Version {
			t.Fatal("version unchanged")
		}
		if valueCAS(c, "CAS-A", "CAS-B", nil) != nil {
			t.Fatal("expected unguarded unrelated change not observed")
		}
		if read(t).Values["sn"][0] != "External-Surname" {
			t.Fatal("unexpected field replacement")
		}
	})
	t.Run("case_matching_is_not_byte_matching", func(t *testing.T) {
		reset(t)
		replace(t, "displayName", "Alpha")
		if valueCAS(c, "ALPHA", "Beta", nil) != nil {
			t.Fatal("expected case-insensitive deletion not observed")
		}
		t.Log("directory equality accepts ALPHA for stored Alpha: not a byte-exact precondition")
	})
	t.Run("permissive_modify_destroys_guard", func(t *testing.T) {
		reset(t)
		controls := []ldap.Control{ldapCriticalProbe{ldap.NewControlString("1.2.840.113556.1.4.1413", true, "")}}
		req := ldap.NewModifyRequest(original.DN, controls)
		req.Delete("displayName", []string{"wrong-old"})
		req.Replace("displayName", []string{"unsafe-overwrite"})
		if c.Modify(req) != nil {
			t.Fatal("expected permissive stale-delete acceptance not observed")
		}
		if read(t).Values["displayName"][0] != "unsafe-overwrite" {
			t.Fatal("permissive probe not exercised")
		}
	})
	t.Run("version_attribute_write_is_not_least_privilege", func(t *testing.T) {
		reset(t)
		before := read(t)
		req := ldap.NewModifyRequest(original.DN, nil)
		req.Delete("uSNChanged", []string{before.Version})
		req.Add("uSNChanged", []string{before.Version})
		req.Replace("displayName", []string{"must-not-write"})
		e := c.Modify(req)
		var result *ldap.Error
		if !errors.As(e, &result) || (result.ResultCode != ldap.LDAPResultConstraintViolation && result.ResultCode != ldap.LDAPResultInsufficientAccessRights && result.ResultCode != ldap.LDAPResultUnwillingToPerform) {
			t.Fatal("system attribute probe did not return a definitive schema/rights rejection")
		}
		t.Logf("system version write rejected with LDAP result=%d", result.ResultCode)
		if !reflect.DeepEqual(read(t), before) {
			t.Fatal("rejected version probe mutated target")
		}
	})
	restore(t)
	if d.Ready(ctx) == nil {
		t.Fatal("runtime CAS gate unexpectedly opened")
	}
	t.Log("Research complete; original four values restored; runtime gate unchanged")
}
