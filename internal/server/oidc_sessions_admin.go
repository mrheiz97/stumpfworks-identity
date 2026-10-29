package server

import (
	"database/sql"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
)

var oidcSessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

type oidcSessionView struct {
	SessionID, ClientID, Username, Scope, Status string
	IssuedAt, ExpiresAt                          time.Time
	Revocable                                    bool
}

type oidcSessionsPageData struct {
	Sessions             []oidcSessionView
	ActiveUsers, Clients []string
	CSRF, Status         string
	CanRevoke            bool
}

func (s *Server) oidcSessionsPage(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	sessions, err := s.store.OIDCSessions(r.Context(), now)
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "oidc_sessions_unavailable")
		return
	}
	views := make([]oidcSessionView, 0, len(sessions))
	users, clients := map[string]struct{}{}, map[string]struct{}{}
	canRevoke := requestCan(r, adminauth.PermissionOIDCSessionsRevoke)
	for _, session := range sessions {
		status := "Active"
		revocable := canRevoke
		if session.RevokedAt.Valid {
			status, revocable = "Revoked", false
		} else if !session.ExpiresAt.After(now) {
			status, revocable = "Expired", false
		} else {
			users[session.Username], clients[session.ClientID] = struct{}{}, struct{}{}
		}
		views = append(views, oidcSessionView{SessionID: session.SessionID, ClientID: session.ClientID, Username: session.Username, Scope: session.Scope, Status: status, IssuedAt: session.IssuedAt, ExpiresAt: session.ExpiresAt, Revocable: revocable})
	}
	activeUsers, activeClients := mapKeys(users), mapKeys(clients)
	csrf := ""
	if token := administrativeCookieToken(r); token != "" {
		csrf = s.sessions.CSRF(token)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderCompactAdminPage(w, r, oidcSessionsTemplate, oidcSessionsPageData{Sessions: views, ActiveUsers: activeUsers, Clients: activeClients, CSRF: csrf, Status: r.URL.Query().Get("status"), CanRevoke: canRevoke}, "/oidc-sessions"); err != nil {
		s.log.Error("OIDC sessions page rendering failed", "error", err)
	}
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (s *Server) revokeOIDCSessionsByUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	if !loginUsername.MatchString(username) {
		s.problem(w, http.StatusBadRequest, "invalid_oidc_session_user")
		return
	}
	count, err := s.store.RevokeOIDCSessionsByUserWithAudit(r.Context(), username, remoteIP(r))
	s.finishBulkOIDCRevocation(w, r, count, err)
}

func (s *Server) revokeOIDCSessionsByClient(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	if !oidcClientIDPattern.MatchString(clientID) {
		s.problem(w, http.StatusBadRequest, "invalid_oidc_session_client")
		return
	}
	count, err := s.store.RevokeOIDCSessionsByClientWithAudit(r.Context(), clientID, remoteIP(r))
	s.finishBulkOIDCRevocation(w, r, count, err)
}

func (s *Server) revokeAllOIDCSessions(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("confirmation") != "revoke-all" {
		s.problem(w, http.StatusBadRequest, "oidc_global_revocation_confirmation_required")
		return
	}
	count, err := s.store.RevokeAllOIDCSessionsWithAudit(r.Context(), remoteIP(r))
	s.finishBulkOIDCRevocation(w, r, count, err)
}

func (s *Server) finishBulkOIDCRevocation(w http.ResponseWriter, r *http.Request, count int64, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		http.Redirect(w, r, "/oidc-sessions?status=none", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.log.Error("OIDC bulk session revocation failed", "component", "oidc")
		s.problem(w, http.StatusServiceUnavailable, "oidc_session_revocation_failed")
		return
	}
	http.Redirect(w, r, "/oidc-sessions?status="+url.QueryEscape("revoked-"+strconv.FormatInt(count, 10)), http.StatusSeeOther)
}

func (s *Server) revokeOIDCSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if !oidcSessionIDPattern.MatchString(sessionID) {
		s.problem(w, http.StatusBadRequest, "invalid_oidc_session")
		return
	}
	if err := s.store.RevokeOIDCSessionWithAudit(r.Context(), sessionID, remoteIP(r), "admin_revocation"); err != nil {
		s.log.Error("OIDC session revocation failed", "error", err)
		s.problem(w, http.StatusServiceUnavailable, "oidc_session_revocation_failed")
		return
	}
	http.Redirect(w, r, "/oidc-sessions", http.StatusSeeOther)
}

var oidcSessionsTemplate = template.Must(template.New("oidc-sessions").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>OIDC sessions · StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="content" style="max-width:1100px;margin:auto"><header class="topbar"><div><p class="eyebrow">STUMPFWORKS / IDENTITY</p><h1>OIDC sessions</h1></div><div><a class="button secondary" href="/oidc-clients">Clients</a> <a class="button secondary" href="/">Dashboard</a></div></header>{{if .Status}}<div class="notice success-notice">Session revocation completed.</div>{{end}}{{if .CanRevoke}}<section class="panel"><div class="panel-head"><div><h2>Central revocation</h2><p>Revoke every active session for one identity or application. Global revocation requires explicit confirmation.</p></div></div><div class="grid"><form method="post" action="/oidc-sessions/revoke-user"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label><span>User</span><select name="username" required>{{range .ActiveUsers}}<option>{{.}}</option>{{end}}</select></label><button class="danger small" type="submit">Revoke user sessions</button></form><form method="post" action="/oidc-sessions/revoke-client"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label><span>Client</span><select name="client_id" required>{{range .Clients}}<option>{{.}}</option>{{end}}</select></label><button class="danger small" type="submit">Revoke client sessions</button></form><form method="post" action="/oidc-sessions/revoke-all"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label><span>Emergency confirmation</span><input name="confirmation" autocomplete="off" placeholder="revoke-all" required></label><button class="danger small" type="submit">Revoke every active session</button></form></div></section>{{end}}<section class="panel"><div class="panel-head"><div><h2>Issued sessions</h2><p>Opaque access tokens are stored only as hashes. Revocation becomes effective on token introspection.</p></div></div><div class="table-wrap"><table><thead><tr><th>Session</th><th>User</th><th>Client</th><th>Issued</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody>{{range .Sessions}}<tr><td class="mono">{{.SessionID}}</td><td><strong>{{.Username}}</strong></td><td>{{.ClientID}}</td><td class="muted">{{.IssuedAt}}</td><td class="muted">{{.ExpiresAt}}</td><td><span class="badge {{if eq .Status "Active"}}success{{else}}neutral{{end}}">{{.Status}}</span></td><td class="actions">{{if .Revocable}}<form method="post" action="/oidc-sessions/{{.SessionID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="danger small" type="submit">Revoke</button></form>{{end}}</td></tr>{{else}}<tr><td class="empty" colspan="7">No OIDC sessions issued.</td></tr>{{end}}</tbody></table></div></section></main></body></html>`))
