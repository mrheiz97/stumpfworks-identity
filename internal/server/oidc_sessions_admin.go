package server

import (
	"html/template"
	"net/http"
	"regexp"
	"time"
)

var oidcSessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

type oidcSessionView struct {
	SessionID, ClientID, Username, Scope, Status string
	IssuedAt, ExpiresAt                          time.Time
	Revocable                                    bool
}

type oidcSessionsPageData struct {
	Sessions []oidcSessionView
	CSRF     string
}

func (s *Server) oidcSessionsPage(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	sessions, err := s.store.OIDCSessions(r.Context(), now)
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "oidc_sessions_unavailable")
		return
	}
	views := make([]oidcSessionView, 0, len(sessions))
	for _, session := range sessions {
		status := "Active"
		revocable := true
		if session.RevokedAt.Valid {
			status, revocable = "Revoked", false
		} else if !session.ExpiresAt.After(now) {
			status, revocable = "Expired", false
		}
		views = append(views, oidcSessionView{SessionID: session.SessionID, ClientID: session.ClientID, Username: session.Username, Scope: session.Scope, Status: status, IssuedAt: session.IssuedAt, ExpiresAt: session.ExpiresAt, Revocable: revocable})
	}
	csrf := ""
	if cookie, err := r.Cookie("swbadge_admin"); err == nil {
		csrf = s.sessions.CSRF(cookie.Value)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := oidcSessionsTemplate.Execute(w, oidcSessionsPageData{Sessions: views, CSRF: csrf}); err != nil {
		s.log.Error("OIDC sessions page rendering failed", "error", err)
	}
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

var oidcSessionsTemplate = template.Must(template.New("oidc-sessions").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>OIDC sessions · StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="content" style="max-width:1100px;margin:auto"><header class="topbar"><div><p class="eyebrow">STUMPFWORKS / IDENTITY</p><h1>OIDC sessions</h1></div><div><a class="button secondary" href="/oidc-clients">Clients</a> <a class="button secondary" href="/">Dashboard</a></div></header><section class="panel"><div class="panel-head"><div><h2>Issued sessions</h2><p>Opaque access tokens are stored only as hashes. Revocation becomes effective on token introspection.</p></div></div><div class="table-wrap"><table><thead><tr><th>Session</th><th>User</th><th>Client</th><th>Issued</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody>{{range .Sessions}}<tr><td class="mono">{{.SessionID}}</td><td><strong>{{.Username}}</strong></td><td>{{.ClientID}}</td><td class="muted">{{.IssuedAt}}</td><td class="muted">{{.ExpiresAt}}</td><td><span class="badge {{if eq .Status "Active"}}success{{else}}neutral{{end}}">{{.Status}}</span></td><td class="actions">{{if .Revocable}}<form method="post" action="/oidc-sessions/{{.SessionID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="danger small" type="submit">Revoke</button></form>{{end}}</td></tr>{{else}}<tr><td class="empty" colspan="7">No OIDC sessions issued.</td></tr>{{end}}</tbody></table></div></section></main></body></html>`))
