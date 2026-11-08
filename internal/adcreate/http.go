package adcreate

import (
	"crypto/hmac"
	"html/template"
	"net/http"
)

// A host must supply a verified normal
// AD session and a session-bound CSRF token; nil callbacks deny all requests.
// Fresh AD credentials are checked again by Service for every operation.
type Handler struct {
	Service Operations
	Session func(*http.Request) (username, csrf string, err error)
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h.Service == nil || !h.Service.IsEnabled() || h.Session == nil || r.TLS == nil {
		http.Error(w, "Benutzeranlage gesperrt", 403)
		return
	}
	user, csrf, e := h.Session(r)
	if e != nil || user == "" || csrf == "" {
		http.Error(w, "Nicht autorisiert", 403)
		return
	}
	data := struct {
		CSRF, Error string
		Operation   Operation
		Events      []Event
	}{CSRF: csrf}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		if r.Header.Get("Origin") != "https://"+r.Host || r.URL.RawQuery != "" {
			http.Error(w, "Ungültiger Ursprung", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if r.ParseForm() != nil || !hmac.Equal([]byte(r.PostForm.Get("_csrf")), []byte(csrf)) {
			http.Error(w, "Ungültige Anfrage", 403)
			return
		}
		allowed := map[string]bool{"_csrf": true, "action": true, "id": true, "digest": true, "name": true, "display": true, "password": true}
		for k, v := range r.PostForm {
			if !allowed[k] || len(v) != 1 {
				http.Error(w, "Ungültige Anfrage", 400)
				return
			}
		}
		action := r.PostForm.Get("action")
		password := r.PostForm.Get("password")
		if action == "prepare" {
			data.Operation, e = h.Service.Prepare(r.Context(), user, password, Input{Name: r.PostForm.Get("name"), DisplayName: r.PostForm.Get("display")})
		} else {
			data.Operation, e = h.Service.Action(r.Context(), user, password, r.PostForm.Get("id"), action, r.PostForm.Get("digest"))
		}
		if e != nil {
			data.Error = "Abgewiesen oder Ergebnis unklar. Auftrag nur über Status prüfen; nicht erneut anlegen."
		}
		if data.Operation.Plan.ID != "" {
			data.Events, _ = h.Service.History(r.Context(), user, password, data.Operation.Plan.ID)
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Methode nicht erlaubt", 405)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, data)
}

var page = template.Must(template.New("create").Parse(`<!doctype html><html lang="de"><meta charset="utf-8"><title>Benutzer anlegen</title><main><h1>Deaktivierten Benutzer anlegen</h1><p>Feste OU und Vorlage. Passwort, Gruppen und Aktivierung sind separate Schritte.</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
{{if .Operation.Plan.ID}}<p>Auftrag: {{.Operation.Plan.ID}} · Status: {{.Operation.State}}</p>{{if .Operation.Plan.Expires}}<dl><dt>Benutzername</dt><dd>{{.Operation.Plan.Input.Name}}</dd><dt>UPN</dt><dd>{{.Operation.Plan.Input.Name}}@{{.Operation.Plan.Scope.UPNSuffix}}</dd><dt>Anzeigename</dt><dd>{{.Operation.Plan.Input.DisplayName}}</dd><dt>OU-ID</dt><dd>{{.Operation.Plan.Scope.OU}}</dd><dt>Ablauf (Unix)</dt><dd>{{.Operation.Plan.Expires}}</dd></dl>{{end}}{{if eq .Operation.State "prepared"}}<form method="post"><input type="hidden" name="_csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="confirm"><input type="hidden" name="id" value="{{.Operation.Plan.ID}}"><input type="hidden" name="digest" value="{{.Operation.Plan.Digest}}"><label>AD-Passwort <input type="password" name="password" autocomplete="current-password" required></label><button>Plan verbindlich bestätigen</button></form>{{end}}{{end}}
{{if eq .Operation.State "succeeded"}}<p>Deaktiviertes Konto bestätigt angelegt. GUID: {{.Operation.Result.GUID}} · SID: {{.Operation.Result.SID}}</p>{{end}}
{{if and (ne .Operation.State "uncertain") (ne .Operation.State "applying")}}<h2>Neuer Plan</h2><form method="post"><input type="hidden" name="_csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="prepare"><label>Benutzername <input name="name" pattern="[a-z][a-z0-9._-]{0,19}" maxlength="20" required></label><label>Anzeigename <input name="display" maxlength="256" required></label><label>AD-Passwort <input type="password" name="password" autocomplete="current-password" required></label><button>Plan erstellen</button></form>
{{end}}<h2>Status / Abbruch</h2><form method="post"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label>Auftrag-ID <input name="id" value="{{.Operation.Plan.ID}}" pattern="[a-f0-9]{32}" required></label><select name="action"><option value="status">Status ohne erneuten Versand</option><option value="evidence">DC-Beleg lesend prüfen</option><option value="cancel">Plan abbrechen</option></select><label>AD-Passwort <input type="password" name="password" autocomplete="current-password" required></label><button>Prüfen</button></form>
{{with .Operation.Evidence}}<p>Signierter DC-Beleg: GUID {{.GUID}}, SID {{.SID}}, Commit-Version {{.Version}}. Der Auftragsstatus und seine Sperre bleiben bestehen.</p>{{end}}{{if .Events}}<h2>Audit</h2><ol>{{range .Events}}<li>{{.At}} · {{.Event}}</li>{{end}}</ol>{{end}}</main></html>`))
