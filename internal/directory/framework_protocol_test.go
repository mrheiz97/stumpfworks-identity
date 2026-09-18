package directory

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	frameworkldap "github.com/TheRealHZL/stumpfworks-framework/directory/ldap"
	ber "github.com/go-asn1-ber/asn1-ber"
)

// This is a synthetic TLS/LDAP server, not an AD deployment or auth fixture.
func identityLDAPFixture(t *testing.T, count int) LDAP {
	t.Helper()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certServer.TLS.Certificates[0]
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certServer.Certificate().Raw})
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reply := func(id interface{}, operation *ber.Packet) {
			message := ber.NewSequence("")
			message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
			message.AppendChild(operation)
			_, _ = conn.Write(message.Bytes())
		}
		result := func(tag ber.Tag) *ber.Packet {
			p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
			p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
			return p
		}
		request, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		reply(request.Children[0].Value, result(1))
		request, err = ber.ReadPacket(conn)
		if err != nil {
			return
		}
		id := request.Children[0].Value
		for i := 0; i < count; i++ {
			entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
			entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "CN=Alice,DC=example,DC=test", ""))
			attributes := ber.NewSequence("")
			for _, pair := range [][2]string{{"sAMAccountName", "alice"}, {"displayName", "Alice"}, {"mail", "alice@example.test"}} {
				attribute := ber.NewSequence("")
				attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, pair[0], ""))
				values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
				values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, pair[1], ""))
				attribute.AppendChild(values)
				attributes.AppendChild(attribute)
			}
			entry.AppendChild(attributes)
			reply(id, entry)
		}
		reply(id, result(5))
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	return LDAP{URL: "ldaps://" + listener.Addr().String(), BaseDN: "DC=example,DC=test", BindDN: "CN=service,DC=example,DC=test", BindPassword: "synthetic", CAFile: caFile}
}

func TestFrameworkLookupOverVerifiedLocalTLS(t *testing.T) {
	for _, tc := range []struct {
		name      string
		count     int
		untrusted bool
		want      error
	}{
		{"one", 1, false, nil}, {"missing", 0, false, ErrUserNotFound},
		{"ambiguous", 2, false, frameworkldap.ErrAmbiguous},
		{"untrusted", 1, true, frameworkldap.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := identityLDAPFixture(t, tc.count)
			if tc.untrusted {
				config.CAFile = ""
			}
			d, err := config.WithFrameworkLookups()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			u, err := d.GetUser(ctx, "alice")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.want != nil {
				if u != nil {
					t.Fatal("failed lookup returned user")
				}
				return
			}
			if u == nil || *u != (User{Username: "alice", DisplayName: "Alice", DN: "CN=Alice,DC=example,DC=test", Mail: "alice@example.test"}) {
				t.Fatal("TLS lookup projection changed")
			}
		})
	}
}
