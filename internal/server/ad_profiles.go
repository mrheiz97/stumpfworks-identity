package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adprofile"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
)

// ConfigureADProfiles passes only a local endpoint, never writer credentials.
func (s *Server) ConfigureADProfiles(socket string) error {
	if socket != "" && (!filepath.IsAbs(socket) || !s.protect) {
		return adprofile.ErrDenied
	}
	s.profileSocket = socket
	return nil
}
func (s *Server) adProfiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.profileSocket == "" {
		s.problem(w, 403, "ad_profiles_disabled")
		return
	}
	if !s.protect || s.sessions == nil {
		s.problem(w, 403, "ad_profiles_denied")
		return
	}
	if c, err := r.Cookie("swbadge_emergency_admin"); err == nil && c.Value != "" {
		s.problem(w, 403, "ad_profiles_denied")
		return
	}
	if _, ok := s.dir.(directory.AdministrativeDirectory); !ok {
		s.problem(w, 403, "ad_profiles_denied")
		return
	}
	cookie, e := r.Cookie("swbadge_admin")
	if e != nil {
		s.problem(w, 403, "ad_profiles_denied")
		return
	}
	username, e := s.sessions.Verify(cookie.Value, time.Now())
	if e != nil {
		s.problem(w, 403, "ad_profiles_denied")
		return
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		s.problem(w, 503, "unavailable")
		return
	}
	data := map[string]any{"ID": hex.EncodeToString(nonce), "CSRF": s.sessions.CSRF(cookie.Value)}
	if r.Method == "POST" {
		// Same-origin HTTPS is mandatory even when a valid CSRF token was supplied.
		if r.TLS == nil || r.Header.Get("Origin") != "https://"+r.Host {
			s.problem(w, 403, "origin_invalid")
			return
		}
		if r.ParseForm() != nil || len(r.URL.Query()) != 0 {
			s.problem(w, 400, "invalid_profile_request")
			return
		}
		allowed := map[string]bool{"_csrf": true, "action": true, "id": true, "target": true, "password": true, "displayName": true, "givenName": true, "sn": true, "mail": true, "parent": true}
		for k, v := range r.PostForm {
			if !allowed[k] || len(v) != 1 {
				s.problem(w, 400, "invalid_profile_request")
				return
			}
		}
		request := adprofile.Request{Action: r.PostForm.Get("action"), ID: r.PostForm.Get("id"), Target: r.PostForm.Get("target"), Username: username, Password: r.PostForm.Get("password"), Parent: r.PostForm.Get("parent")}
		if request.Action == "prepare" {
			request.Changes = adprofile.Values{}
			for _, a := range []string{"displayName", "givenName", "sn", "mail"} {
				if v, ok := r.PostForm[a]; ok {
					request.Changes[a] = []string{}
					if v[0] != "" {
						request.Changes[a] = []string{v[0]}
					}
				}
			}
		}
		body, e := json.Marshal(request)
		if e != nil {
			s.problem(w, 400, "invalid_profile_request")
			return
		}
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", s.profileSocket)
		}}
		defer transport.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://executor/operation", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Transport: transport}).Do(req)
		data["OperationID"] = request.ID
		if err != nil {
			data["Error"] = "Ergebnis unklar. Auftrag nur über Status prüfen; nicht erneut planen."
			data["OperationID"] = request.ID
		} else {
			defer response.Body.Close()
			var result adprofile.Response
			if json.NewDecoder(http.MaxBytesReader(w, response.Body, 65536)).Decode(&result) != nil {
				data["Error"] = "Ergebnis unklar. Status des Auftrags prüfen."
			} else {
				data["Result"] = result
				data["Target"] = request.Target
				data["OperationID"] = request.ID
				if result.Error != "" {
					data["Error"] = "Nicht ausgeführt oder Ergebnis unklar. Status prüfen; keine automatische Wiederholung."
				}
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderCompactAdminPage(w, r, template.Must(template.New("profile").Parse(adProfileTemplate)), data, "/ad-profiles"); err != nil {
		s.log.Error("AD profile page unavailable")
	}
}

const adProfileTemplate = `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AD-Profile</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="content"><section class="panel"><a href="/">Identity</a><h1>AD-Profilbearbeitung · Stufe 1</h1><p>Nur freigegebene gewöhnliche Konten. Jede Aktion verlangt die aktuelle AD-Anmeldung. Andere Kontofunktionen sind gesperrt.</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}{{if .OperationID}}<p>Auftrag: {{.OperationID}}</p>{{end}}
{{with .Result}}<p>Status: {{.Operation.State}}</p>{{if .Before}}<table><caption>Vorher / geplant</caption><tr><th>Attribut</th><th>Vorher</th><th>Geplant</th></tr>{{range $a,$v:=.Before}}<tr><th>{{$a}}</th><td>{{$v}}</td><td>{{index $.Result.After $a}}</td></tr>{{end}}</table>{{end}}{{end}}
<h2>Profil laden</h2><form method="post"><input type="hidden" name="_csrf" value="{{.CSRF}}"><input type="hidden" name="id" value="{{.ID}}"><input type="hidden" name="action" value="read"><label>Ziel-ID <input name="target" value="{{.Target}}" required pattern="[a-f0-9]{32}"></label><label>AD-Passwort <input type="password" name="password" autocomplete="current-password" required></label><button>Laden</button></form>
{{with .Result}}{{if .Before}}<h2>Änderung vorbereiten</h2><p>Leere Felder entfernen den Wert. E-Mail-Änderungen vorab mit den angebundenen Anwendungen abstimmen.</p><form method="post"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{$.ID}}"><input type="hidden" name="target" value="{{.Operation.Target}}"><input type="hidden" name="action" value="prepare">{{range $a,$v:=.Before}}<label>{{$a}} <input name="{{$a}}" value="{{if $v}}{{index $v 0}}{{end}}" maxlength="254"></label>{{end}}<label>AD-Passwort <input type="password" name="password" autocomplete="current-password" required></label><button>Plan erstellen</button></form>{{end}}{{if eq .Operation.State "prepared"}}<h2>Plan bestätigen</h2><p>Prüfe die geplanten Werte oben. Die Bestätigung gilt nur für diesen Auftrag und höchstens fünf Minuten.</p><form method="post"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.Operation.ID}}"><input type="hidden" name="action" value="apply"><label>AD-Passwort <input type="password" name="password" autocomplete="current-password" required></label><button>Änderung verbindlich ausführen</button></form>{{end}}{{end}}
{{with .Result}}{{if or (eq .Operation.State "succeeded") (eq .Operation.State "reconciled_effect_observed")}}<h2>Rückweg vorbereiten</h2><p>Die aktuellen Werte müssen noch genau den von uns gesetzten Werten entsprechen. Erst der neue Plan darf die Gegenänderung ausführen.</p><form method="post"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{$.ID}}"><input type="hidden" name="parent" value="{{.Operation.ID}}"><input type="hidden" name="action" value="rollback-plan"><label>AD-Passwort <input type="password" name="password" autocomplete="current-password" required></label><button>Gegenänderung planen</button></form>{{end}}{{if .Events}}<h2>Auftragsaudit</h2><p>Bis zu 100 neueste Ereignisse. Gleiche Sekundenzeitpunkte legen keine Reihenfolge fest; das vollständige Journal bleibt erhalten.</p><table><tr><th>Zeit (UTC Unix)</th><th>Ereignis</th><th>Metadaten</th></tr>{{range .Events}}<tr><td>{{.At}}</td><td>{{.Event}}</td><td>{{.Metadata}}</td></tr>{{end}}</table>{{end}}{{end}}
<h2>Auftrag prüfen oder abbrechen</h2><form method="post"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label>Auftrag-ID <input name="id" value="{{.OperationID}}" required pattern="[a-f0-9]{32}"></label><label>Aktion <select name="action"><option value="status">Status</option><option value="cancel">Vor Ausführung abbrechen</option><option value="reconcile">Unklares Ergebnis lesend klären</option></select></label><label>AD-Passwort <input type="password" name="password" autocomplete="current-password" required></label><button>Prüfen</button></form><p>Ein Rückweg ist eine neue vorbereitete und bestätigte Gegenänderung. Fremdänderungen dürfen nicht überschrieben werden.</p></section></main></body></html>`
