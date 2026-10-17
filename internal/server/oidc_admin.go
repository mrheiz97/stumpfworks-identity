package server

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var oidcClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type oidcClientView struct {
	ClientID, RedirectURIs, Scopes string
	Enabled                        bool
}

type oidcClientsPageData struct {
	Clients                        []oidcClientView
	CSRF, Secret, SecretID, Notice string
}

func (s *Server) oidcClientsPage(w http.ResponseWriter, r *http.Request) {
	s.renderOIDCClients(w, r, "", "", "")
}

func (s *Server) createOIDCClient(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.FormValue("client_id"))
	redirects, scopes, ok := validOIDCClientInput(id, r.FormValue("redirect_uris"), r.FormValue("scopes"))
	if !ok {
		s.problem(w, http.StatusBadRequest, "invalid_oidc_client")
		return
	}
	secret, hash, ok := newOIDCClientSecret()
	if !ok {
		s.problem(w, http.StatusServiceUnavailable, "oidc_client_creation_failed")
		return
	}
	if err := s.store.CreateOIDCClientWithAudit(r.Context(), id, hash, redirects, scopes, remoteIP(r)); err != nil {
		s.log.Error("OIDC client creation failed", "error", err)
		s.problem(w, http.StatusServiceUnavailable, "oidc_client_creation_failed")
		return
	}
	s.renderOIDCClients(w, r, id, secret, "Client created. Store this secret now; it will not be shown again.")
}

func (s *Server) rotateOIDCClientSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !oidcClientIDPattern.MatchString(id) {
		s.problem(w, http.StatusBadRequest, "invalid_oidc_client")
		return
	}
	secret, hash, ok := newOIDCClientSecret()
	if !ok {
		s.problem(w, http.StatusServiceUnavailable, "oidc_client_rotation_failed")
		return
	}
	if err := s.store.RotateOIDCClientSecretWithAudit(r.Context(), id, hash, remoteIP(r)); err != nil {
		s.log.Error("OIDC client secret rotation failed", "client_id", id, "error", err)
		s.problem(w, http.StatusServiceUnavailable, "oidc_client_rotation_failed")
		return
	}
	s.renderOIDCClients(w, r, id, secret, "Secret rotated. Update the application before leaving this page.")
}

func (s *Server) updateOIDCClientConfiguration(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	redirects, scopes, ok := validOIDCClientInput(id, r.FormValue("redirect_uris"), r.FormValue("scopes"))
	if !ok {
		s.problem(w, http.StatusBadRequest, "invalid_oidc_client")
		return
	}
	if err := s.store.UpdateOIDCClientConfigurationWithAudit(r.Context(), id, redirects, scopes, remoteIP(r)); err != nil {
		s.log.Error("OIDC client configuration update failed", "client_id", id, "error", err)
		s.problem(w, http.StatusServiceUnavailable, "oidc_client_configuration_failed")
		return
	}
	http.Redirect(w, r, "/oidc-clients", http.StatusSeeOther)
}

func (s *Server) enableOIDCClient(w http.ResponseWriter, r *http.Request) {
	s.setOIDCClientEnabled(w, r, true)
}
func (s *Server) disableOIDCClient(w http.ResponseWriter, r *http.Request) {
	s.setOIDCClientEnabled(w, r, false)
}

func (s *Server) setOIDCClientEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	id := r.PathValue("id")
	if !oidcClientIDPattern.MatchString(id) {
		s.problem(w, http.StatusBadRequest, "invalid_oidc_client")
		return
	}
	if err := s.store.SetOIDCClientEnabledWithAudit(r.Context(), id, enabled, remoteIP(r)); err != nil {
		s.log.Error("OIDC client state change failed", "client_id", id, "error", err)
		s.problem(w, http.StatusServiceUnavailable, "oidc_client_state_failed")
		return
	}
	http.Redirect(w, r, "/oidc-clients", http.StatusSeeOther)
}

func (s *Server) renderOIDCClients(w http.ResponseWriter, r *http.Request, secretID, secret, notice string) {
	clients, err := s.store.OIDCClients(r.Context())
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "oidc_clients_unavailable")
		return
	}
	views := make([]oidcClientView, 0, len(clients))
	for _, c := range clients {
		views = append(views, oidcClientView{ClientID: c.ClientID, RedirectURIs: c.RedirectURIs, Scopes: c.Scopes, Enabled: c.Enabled})
	}
	csrf := ""
	if cookie, err := r.Cookie("swbadge_admin"); err == nil {
		csrf = s.sessions.CSRF(cookie.Value)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := oidcClientsTemplate.Execute(w, oidcClientsPageData{Clients: views, CSRF: csrf, SecretID: secretID, Secret: secret, Notice: notice}); err != nil {
		s.log.Error("OIDC client page rendering failed", "error", err)
	}
}

func validOIDCClientInput(id, redirectInput, scopeInput string) (string, string, bool) {
	if !oidcClientIDPattern.MatchString(id) {
		return "", "", false
	}
	var redirects []string
	for _, line := range strings.Split(strings.ReplaceAll(redirectInput, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(line) > 2048 || slices.Contains(redirects, line) {
			return "", "", false
		}
		redirects = append(redirects, line)
	}
	if len(redirects) == 0 || len(redirects) > 20 {
		return "", "", false
	}
	scopes := strings.Fields(scopeInput)
	if len(scopes) == 0 || len(scopes) > 3 || !slices.Contains(scopes, "openid") {
		return "", "", false
	}
	for _, scope := range scopes {
		if scope != "openid" && scope != "profile" && scope != "email" {
			return "", "", false
		}
	}
	return strings.Join(redirects, "\n"), strings.Join(scopes, " "), true
}

func newOIDCClientSecret() (string, string, bool) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", false
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", false
	}
	return secret, string(hash), true
}

var oidcClientsTemplate = template.Must(template.New("oidc-clients").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>OIDC clients · StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="content" style="max-width:1100px;margin:auto"><header class="topbar"><div><p class="eyebrow">STUMPFWORKS / IDENTITY</p><h1>OIDC clients</h1></div><a class="button secondary" href="/">Dashboard</a></header>{{if .Secret}}<section class="panel secret"><div><span class="badge warning">One-time secret</span><h2>{{.SecretID}}</h2><p>{{.Notice}}</p><code id="oidc-client-secret">{{.Secret}}</code></div></section>{{end}}<section class="panel"><div class="panel-head"><div><h2>Register client</h2><p>Redirect URIs must be exact HTTPS URLs. Secrets are displayed once.</p></div></div><form method="post" action="/oidc-clients"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label><span>Client ID</span><input name="client_id" required pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,127}"></label><label><span>Redirect URIs (one per line)</span><textarea name="redirect_uris" required rows="3"></textarea></label><label><span>Scopes</span><input name="scopes" value="openid profile email" required></label><button type="submit">Register client</button></form></section><section class="panel"><div class="panel-head"><div><h2>Registered clients</h2><p>Each application has its own exact redirect allowlist. Secret hashes are never exposed.</p></div></div><div class="table-wrap"><table><thead><tr><th>Client</th><th>Redirect URIs and scopes</th><th>Status</th><th></th></tr></thead><tbody>{{range .Clients}}<tr><td><strong>{{.ClientID}}</strong></td><td><form method="post" action="/oidc-clients/{{.ClientID}}/configure"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><label><span>Exact HTTPS redirect URIs (one per line)</span><textarea class="mono" name="redirect_uris" required rows="3">{{.RedirectURIs}}</textarea></label><label><span>Scopes</span><input name="scopes" value="{{.Scopes}}" required></label><button class="small" type="submit">Save configuration</button></form></td><td>{{if .Enabled}}<span class="badge success">Enabled</span>{{else}}<span class="badge neutral">Disabled</span>{{end}}</td><td class="actions"><form method="post" action="/oidc-clients/{{.ClientID}}/rotate-secret"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="small" type="submit">Rotate secret</button></form><form method="post" action="/oidc-clients/{{.ClientID}}/{{if .Enabled}}disable{{else}}enable{{end}}"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="small {{if .Enabled}}danger{{end}}" type="submit">{{if .Enabled}}Disable{{else}}Enable{{end}}</button></form></td></tr>{{else}}<tr><td class="empty" colspan="4">No OIDC clients registered.</td></tr>{{end}}</tbody></table></div></section></main></body></html>`))
