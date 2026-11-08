// Package adcreateipc transports typed operations over an authenticated local
// Unix socket. It installs no AD adapter, service unit or automatic retry.
package adcreateipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Identity struct{ UID, GID uint32 }
type Config struct {
	Enabled bool
	Socket  string
	Peer    *Identity // kernel peer credentials, mandatory when enabled
	Owner   *Identity // socket/directory owner and shared socket group
}
type ExecutorOperations interface {
	adcreate.Operations
	PrepareWithID(context.Context, string, string, string, adcreate.Input) (adcreate.Operation, error)
}
type input struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}
type request struct {
	Version      int    `json:"version"`
	Action       string `json:"action"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	ID           string `json:"id,omitempty"`
	Confirmation string `json:"confirmation,omitempty"`
	Input        *input `json:"input,omitempty"`
}
type response struct {
	Version   int                 `json:"version"`
	Operation *adcreate.Operation `json:"operation,omitempty"`
	Events    []adcreate.Event    `json:"events,omitempty"`
	Error     string              `json:"error,omitempty"`
}

const endpoint = "/v1/create"
const maxRequest = 8192
const maxResponse = 65536

type peerKey struct{}

// strictJSON rejects duplicates (including case aliases), unknown fields,
// trailing JSON and excessive nesting. Errors never reach the response/log.
func strictJSON(raw []byte, value any) error {
	if !utf8.Valid(raw) {
		return adcreate.ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 10 {
			return adcreate.ErrDenied
		}
		token, e := d.Token()
		if e != nil {
			return e
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return e
					}
					name, ok := key.(string)
					if !ok || seen[strings.ToLower(name)] {
						return adcreate.ErrDenied
					}
					seen[strings.ToLower(name)] = true
					if e = visit(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return adcreate.ErrDenied
				}
			case '[':
				for d.More() {
					if e := visit(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return adcreate.ErrDenied
				}
			default:
				return adcreate.ErrDenied
			}
		}
		return nil
	}
	if visit(0) != nil {
		return adcreate.ErrDenied
	}
	if _, e := d.Token(); e != io.EOF {
		return adcreate.ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return adcreate.ErrDenied
	}
	return nil
}
func validRequest(r request) bool {
	if r.Version != 1 || len(r.Username) == 0 || len(r.Username) > 64 || len(r.Password) == 0 || len(r.Password) > 1024 {
		return false
	}
	switch r.Action {
	case "prepare":
		return r.Input != nil && validHex(r.ID, 32) && r.Confirmation == "" && len(r.Input.Name) <= 20 && len(r.Input.DisplayName) <= 256
	case "status", "evidence", "cancel", "history":
		return r.Input == nil && r.Confirmation == "" && validHex(r.ID, 32)
	case "confirm":
		return r.Input == nil && validHex(r.ID, 32) && validHex(r.Confirmation, 64)
	}
	return false
}
func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func rpcHandler(backend adcreate.Operations, peer Identity) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		reply := response{Version: 1}
		status := http.StatusForbidden
		defer func() {
			raw, e := json.Marshal(reply)
			if e != nil || len(raw) > maxResponse {
				status = http.StatusConflict
				raw = []byte(`{"version":1,"error":"uncertain"}`)
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
			w.WriteHeader(status)
			_, _ = w.Write(raw)
		}()
		authenticated, ok := r.Context().Value(peerKey{}).(Identity)
		if !ok || authenticated != peer || backend == nil || !backend.IsEnabled() {
			reply.Error = "denied"
			return
		}
		if r.Method != "POST" || r.URL.Path != endpoint || r.URL.RawQuery != "" || r.Host != "executor" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" || len(r.TransferEncoding) > 0 || r.ContentLength < 0 || r.ContentLength > maxRequest {
			reply.Error = "denied"
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
		var message request
		if e != nil || strictJSON(raw, &message) != nil || !validRequest(message) {
			reply.Error = "denied"
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		var operation adcreate.Operation
		switch message.Action {
		case "prepare":
			correlated, ok := backend.(ExecutorOperations)
			if !ok {
				reply.Error = "denied"
				return
			}
			operation, e = correlated.PrepareWithID(ctx, message.Username, message.Password, message.ID, adcreate.Input{Name: message.Input.Name, DisplayName: message.Input.DisplayName})
		case "history":
			reply.Events, e = backend.History(ctx, message.Username, message.Password, message.ID)
		default:
			operation, e = backend.Action(ctx, message.Username, message.Password, message.ID, message.Action, message.Confirmation)
		}
		if operation.Plan.ID != "" {
			reply.Operation = &operation
		}
		switch {
		case e == nil:
			status = http.StatusOK
		case errors.Is(e, adcreate.ErrDenied):
			reply.Error = "denied"
		default:
			status = http.StatusConflict
			reply.Error = "uncertain"
		}
	})
}

type Client struct{ config Config }

func NewClient(c Config) (*Client, error) {
	if c.Enabled && validateConfig(c, false) != nil {
		return nil, adcreate.ErrDenied
	}
	if c.Peer != nil {
		p := *c.Peer
		c.Peer = &p
	}
	if c.Owner != nil {
		o := *c.Owner
		c.Owner = &o
	}
	return &Client{config: c}, nil
}
func (c *Client) IsEnabled() bool { return c != nil && c.config.Enabled }
func (c *Client) call(ctx context.Context, message request) (response, error) {
	var reply response
	if !c.IsEnabled() || !validRequest(message) {
		return reply, adcreate.ErrDenied
	}
	raw, e := json.Marshal(message)
	if e != nil || len(raw) > maxRequest {
		return reply, adcreate.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	// A fresh connection, no proxy, no redirects, no replayable/idempotency headers.
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 4096, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, c.config) }}
	defer transport.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "POST", "http://executor"+endpoint, bytes.NewReader(raw))
	if e != nil {
		return reply, adcreate.ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	result, e := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if e != nil {
		return reply, adcreate.ErrUncertain
	}
	defer result.Body.Close()
	body, e := io.ReadAll(io.LimitReader(result.Body, maxResponse+1))
	if e != nil || len(body) > maxResponse || result.Header.Get("Content-Type") != "application/json" || result.Header.Get("Content-Encoding") != "" || strictJSON(body, &reply) != nil || reply.Version != 1 {
		return response{}, adcreate.ErrUncertain
	}
	if reply.Operation != nil && reply.Operation.Plan.ID != message.ID {
		return response{}, adcreate.ErrUncertain
	}
	if reply.Error == "" {
		if message.Action == "history" {
			if reply.Operation != nil || len(reply.Events) > 100 {
				return response{}, adcreate.ErrUncertain
			}
		} else {
			if reply.Operation == nil || !validHex(reply.Operation.Plan.ID, 32) {
				return response{}, adcreate.ErrUncertain
			}
			switch reply.Operation.State {
			case "prepared", "applying", "uncertain", "succeeded", "cancelled", "expired":
			default:
				return response{}, adcreate.ErrUncertain
			}
			if message.Action == "prepare" && (reply.Operation.Plan.Input.Name != message.Input.Name || reply.Operation.Plan.Input.DisplayName != message.Input.DisplayName || reply.Operation.State != "prepared") {
				return response{}, adcreate.ErrUncertain
			}
		}
	}
	switch {
	case result.StatusCode == 200 && reply.Error == "":
		return reply, nil
	case result.StatusCode == 403 && reply.Error == "denied":
		return reply, adcreate.ErrDenied
	case result.StatusCode == 409 && reply.Error == "uncertain":
		return reply, adcreate.ErrUncertain
	default:
		return response{}, adcreate.ErrUncertain
	}
}
func (c *Client) Prepare(ctx context.Context, user, password string, i adcreate.Input) (adcreate.Operation, error) {
	if !c.IsEnabled() {
		return adcreate.Operation{}, adcreate.ErrDenied
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return adcreate.Operation{}, adcreate.ErrDenied
	}
	id := hex.EncodeToString(nonce[:])
	r, e := c.call(ctx, request{Version: 1, Action: "prepare", Username: user, Password: password, ID: id, Input: &input{Name: i.Name, DisplayName: i.DisplayName}})
	if r.Operation == nil {
		if errors.Is(e, adcreate.ErrUncertain) {
			return adcreate.Operation{Plan: adcreate.Plan{ID: id}, State: "uncertain"}, e
		}
		return adcreate.Operation{}, e
	}
	return *r.Operation, e
}
func (c *Client) Action(ctx context.Context, user, password, id, action, confirmation string) (adcreate.Operation, error) {
	r, e := c.call(ctx, request{Version: 1, Action: action, Username: user, Password: password, ID: id, Confirmation: confirmation})
	if r.Operation == nil {
		return adcreate.Operation{}, e
	}
	return *r.Operation, e
}
func (c *Client) History(ctx context.Context, user, password, id string) ([]adcreate.Event, error) {
	r, e := c.call(ctx, request{Version: 1, Action: "history", Username: user, Password: password, ID: id})
	return r.Events, e
}
