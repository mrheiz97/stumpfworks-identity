package adcreateipc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubOperations struct {
	calls   int
	enabled bool
	fail    error
}

func (s *stubOperations) PrepareWithID(ctx context.Context, user, password, id string, i adcreate.Input) (adcreate.Operation, error) {
	o, e := s.Prepare(ctx, user, password, i)
	o.Plan.ID = id
	return o, e
}

func (s *stubOperations) IsEnabled() bool { return s.enabled }
func (s *stubOperations) Prepare(_ context.Context, user, password string, i adcreate.Input) (adcreate.Operation, error) {
	s.calls++
	return adcreate.Operation{State: "prepared", Plan: adcreate.Plan{ID: strings.Repeat("1", 32), Input: i}}, s.fail
}
func (s *stubOperations) Action(_ context.Context, user, password, id, action, confirmation string) (adcreate.Operation, error) {
	s.calls++
	return adcreate.Operation{State: "uncertain", Plan: adcreate.Plan{ID: id}}, s.fail
}
func (s *stubOperations) History(context.Context, string, string, string) ([]adcreate.Event, error) {
	s.calls++
	return []adcreate.Event{{Event: "prepared", At: 1}}, s.fail
}
func TestDefaultTransportDoesNothing(t *testing.T) {
	c, e := NewClient(Config{Socket: "/never/access/this"})
	if e != nil || c.IsEnabled() {
		t.Fatal("default enabled")
	}
	if _, e = c.Prepare(context.Background(), "actor", "synthetic-secret", adcreate.Input{Name: "new", DisplayName: "New"}); !errors.Is(e, adcreate.ErrDenied) {
		t.Fatal("disabled call")
	}
	if _, e = Listen(Config{}, &stubOperations{enabled: true}); e == nil {
		t.Fatal("disabled listener")
	}
}
func TestRPCProtocolGuardsAndRedaction(t *testing.T) {
	valid := `{"version":1,"action":"prepare","id":"11111111111111111111111111111111","username":"operator","password":"synthetic-secret","input":{"name":"newuser","display_name":"New User"}}`
	for _, mode := range []string{"valid", "peer", "version", "duplicate", "case-duplicate", "nested-duplicate", "unknown", "wire", "trailing", "oversize", "chunked", "query", "host", "method", "content-type", "encoding", "disabled", "backend-error", "denied"} {
		t.Run(mode, func(t *testing.T) {
			raw := valid
			backend := &stubOperations{enabled: true}
			peer := Identity{UID: 12, GID: 34}
			switch mode {
			case "version":
				raw = strings.Replace(raw, `"version":1`, `"version":2`, 1)
			case "duplicate":
				raw = strings.Replace(raw, `"version":1`, `"version":1,"version":1`, 1)
			case "case-duplicate":
				raw = strings.Replace(raw, `"version":1`, `"version":1,"Version":1`, 1)
			case "nested-duplicate":
				raw = strings.Replace(raw, `"name":"newuser"`, `"name":"newuser","name":"other"`, 1)
			case "unknown":
				raw = strings.Replace(raw, `"version":1`, `"version":1,"peer_uid":12`, 1)
			case "wire":
				raw = strings.Replace(raw, `"version":1`, `"version":1,"wire":"arbitrary"`, 1)
			case "trailing":
				raw += `{}`
			case "oversize":
				raw += strings.Repeat(" ", maxRequest)
			case "disabled":
				backend.enabled = false
			case "backend-error":
				backend.fail = errors.New("synthetic-secret")
			case "denied":
				backend.fail = adcreate.ErrDenied
			}
			r := httptest.NewRequest("POST", "http://executor"+endpoint, strings.NewReader(raw))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Peer-UID", "12")
			if mode != "peer" {
				r = r.WithContext(context.WithValue(r.Context(), peerKey{}, peer))
			}
			switch mode {
			case "chunked":
				r.TransferEncoding = []string{"chunked"}
				r.ContentLength = -1
			case "query":
				r.URL.RawQuery = "x=1"
			case "host":
				r.Host = "other"
			case "method":
				r.Method = "GET"
			case "content-type":
				r.Header.Set("Content-Type", "text/plain")
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			}
			w := httptest.NewRecorder()
			rpcHandler(backend, peer).ServeHTTP(w, r)
			if strings.Contains(w.Body.String(), "synthetic-secret") {
				t.Fatal("secret echoed")
			}
			if mode == "valid" {
				if w.Code != 200 || backend.calls != 1 {
					t.Fatal("valid protocol", w.Code)
				}
			} else if mode == "backend-error" {
				if w.Code != 409 || !strings.Contains(w.Body.String(), `"uncertain"`) {
					t.Fatal("error not conservative")
				}
			} else if mode == "denied" {
				if w.Code != 403 {
					t.Fatal("denied mapping")
				}
			} else if backend.calls != 0 || w.Code != 403 {
				t.Fatal("protocol bypass", w.Code, backend.calls)
			}
			var reply response
			if json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Version != 1 {
				t.Fatal("unversioned error")
			}
		})
	}
}
func TestRequestActionsAreClosed(t *testing.T) {
	for _, action := range []string{"delete", "activate", "modify", "retry", "reconcile", "initialize"} {
		r := request{Version: 1, Action: action, Username: "user", Password: "secret", ID: strings.Repeat("1", 32)}
		if validRequest(r) {
			t.Fatal("unsupported action")
		}
	}
}
