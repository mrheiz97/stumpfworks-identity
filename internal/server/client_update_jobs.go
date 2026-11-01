package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"sort"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/deviceauth"
	"github.com/mrheiz97/stumpfworks-framework/web/validation"
)

// ConfigureUpdateCatalog is called once before serving. Artifact approval is
// a deployment operation; the web interface can only choose approved IDs.
func (s *Server) ConfigureUpdateCatalog(c clientupdate.Catalog) { s.updateCatalog = c }
func (s *Server) updateActor(r *http.Request) string {
	if s.sessions != nil {
		if u, e := s.sessions.VerifyFor(administrativeCookieToken(r), "admin", time.Now()); e == nil {
			return u
		}
	}
	return "emergency-admin"
}
func (s *Server) clientUpdatesPage(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.store.ClientUpdateJobs(r.Context(), "")
	if err != nil {
		s.problem(w, 500, "update_jobs_unavailable")
		return
	}
	clients, err := s.store.Clients(r.Context())
	if err != nil {
		s.problem(w, 500, "clients_unavailable")
		return
	}
	eligible := []database.Client{}
	for _, c := range clients {
		if c.Enabled && c.AuthMode != database.ClientAuthTokenOnly {
			eligible = append(eligible, c)
		}
	}
	releases := []clientupdate.ApprovedRelease{}
	for _, v := range s.updateCatalog {
		v.Package = nil
		releases = append(releases, v)
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].ID < releases[j].ID })
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		s.problem(w, 500, "request_id_unavailable")
		return
	}
	csrf := ""
	if s.sessions != nil {
		csrf = s.sessions.CSRF(administrativeCookieToken(r))
	}
	type view struct {
		database.ClientUpdateJob
		Start, End, DisplayState string
		Cancelable               bool
	}
	views := []view{}
	now := time.Now()
	for _, j := range jobs {
		state := string(j.State)
		if j.State == clientupdate.JobScheduled && now.Unix() >= j.ExpiresAt {
			state = "expired (not executed)"
		}
		if j.State == clientupdate.JobDispatched {
			state = "dispatched — awaiting result; do not retry"
		}
		views = append(views, view{j, time.Unix(j.NotBefore, 0).UTC().Format(time.RFC3339), time.Unix(j.ExpiresAt, 0).UTC().Format(time.RFC3339), state, j.State == clientupdate.JobScheduled})
	}
	data := map[string]any{"Jobs": views, "Clients": eligible, "Releases": releases, "RequestID": hex.EncodeToString(raw), "CSRF": csrf, "CanWrite": s.protect && requestCan(r, adminauth.PermissionClientUpdatesWrite), "Enabled": s.updateCatalog != nil}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err = s.renderCompactAdminPage(w, r, clientUpdateJobsTemplate, data, "/client-updates"); err != nil {
		s.log.Error("update jobs template failed")
	}
}
func (s *Server) scheduleClientUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.protect || s.updateCatalog == nil {
		s.problem(w, 403, "updates_disabled")
		return
	}
	if r.ParseForm() != nil || len(r.URL.Query()) != 0 {
		s.problem(w, 400, "invalid_update_job")
		return
	}
	allowed := map[string]bool{"_csrf": true, "id": true, "client_id": true, "release_id": true, "not_before": true, "expires_at": true, "maintenance": true}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			s.problem(w, 400, "invalid_update_job")
			return
		}
	}
	release, ok := s.updateCatalog[r.PostForm.Get("release_id")]
	if !ok {
		s.problem(w, 400, "release_not_approved")
		return
	}
	start, e1 := time.Parse(time.RFC3339, r.PostForm.Get("not_before"))
	end, e2 := time.Parse(time.RFC3339, r.PostForm.Get("expires_at"))
	maintenance := r.PostForm.Get("maintenance")
	window := clientupdate.JobWindow{NotBefore: start, ExpiresAt: end, LightDMMaintenance: maintenance == "confirmed"}
	if e1 != nil || e2 != nil || maintenance != "" && maintenance != "confirmed" || window.Validate(time.Now(), release.RequiresMaintenance) != nil || !validClientID(r.PostForm.Get("client_id")) {
		s.problem(w, 400, "invalid_execution_window")
		return
	}
	j := database.ClientUpdateJob{ID: r.PostForm.Get("id"), ClientID: r.PostForm.Get("client_id"), ReleaseID: release.ID, ReleaseVersion: release.Manifest.ReleaseVersion, PackageSHA256: release.SHA256, NotBefore: start.Unix(), ExpiresAt: end.Unix(), Maintenance: window.LightDMMaintenance}
	if err := s.store.CreateClientUpdateJob(r.Context(), j, s.updateActor(r), remoteIP(r), time.Now()); err != nil {
		s.problem(w, 409, "update_job_not_created")
		return
	}
	http.Redirect(w, r, "/client-updates", http.StatusSeeOther)
}
func (s *Server) cancelClientUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.protect {
		s.problem(w, 403, "updates_disabled")
		return
	}
	if r.ParseForm() != nil || len(r.URL.Query()) != 0 {
		s.problem(w, 400, "invalid_update_cancellation")
		return
	}
	for k, v := range r.PostForm {
		if k != "_csrf" || len(v) != 1 {
			s.problem(w, 400, "invalid_update_cancellation")
			return
		}
	}
	j, err := s.store.ClientUpdateJob(r.Context(), r.PathValue("id"))
	if err != nil {
		s.problem(w, 404, "update_not_found")
		return
	}
	if err = s.store.ChangeClientUpdateJob(r.Context(), j.ID, j.ClientID, clientupdate.JobCancelled, false, s.updateActor(r), remoteIP(r), time.Now()); err != nil {
		s.problem(w, 409, "update_not_cancelable")
		return
	}
	http.Redirect(w, r, "/client-updates", 303)
}
func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request) (database.Client, bool) {
	identity, err := deviceauth.FromTLS(r.TLS, time.Now())
	if err != nil {
		s.problem(w, 401, "invalid_client_credentials")
		return database.Client{}, false
	}
	c, err := s.store.ClientByID(r.Context(), identity.ClientID)
	if err != nil || !c.Enabled || c.AuthMode == database.ClientAuthTokenOnly {
		s.problem(w, 401, "invalid_client_credentials")
		return c, false
	}
	ok, fallback := s.authenticateClientStatus(r, c, time.Now())
	if !ok || fallback {
		s.problem(w, 401, "invalid_client_credentials")
		return c, false
	}
	return c, true
}
func (s *Server) pollClientUpdate(w http.ResponseWriter, r *http.Request) {
	c, ok := s.updateDevice(w, r)
	if !ok {
		return
	}
	jobs, err := s.store.ClientUpdateJobs(r.Context(), c.ClientID)
	if err != nil {
		s.problem(w, 500, "update_jobs_unavailable")
		return
	}
	now := time.Now()
	for _, j := range jobs {
		if j.State == clientupdate.JobScheduled && now.Unix() >= j.ExpiresAt {
			if err = s.store.ChangeClientUpdateJob(r.Context(), j.ID, c.ClientID, clientupdate.JobExpired, false, "", remoteIP(r), now); err != nil {
				s.problem(w, 409, "job_transition_failed")
				return
			}
			continue
		}
		if j.State == clientupdate.JobDispatched || j.State == clientupdate.JobScheduled && now.Unix() >= j.NotBefore {
			if _, ok = s.approvedJob(j); !ok {
				s.problem(w, 409, "release_approval_unavailable")
				return
			}
			s.json(w, 200, j)
			return
		}
	}
	w.WriteHeader(204)
}
func (s *Server) approvedJob(j database.ClientUpdateJob) (clientupdate.ApprovedRelease, bool) {
	v, ok := s.updateCatalog[j.ReleaseID]
	return v, ok && v.SHA256 == j.PackageSHA256 && v.Manifest.ReleaseVersion == j.ReleaseVersion && (!v.RequiresMaintenance || j.Maintenance)
}
func (s *Server) deviceJob(w http.ResponseWriter, r *http.Request) (database.ClientUpdateJob, bool) {
	c, ok := s.updateDevice(w, r)
	if !ok {
		return database.ClientUpdateJob{}, false
	}
	j, err := s.store.ClientUpdateJob(r.Context(), r.PathValue("id"))
	if err != nil || j.ClientID != c.ClientID {
		s.problem(w, 404, "update_not_found")
		return database.ClientUpdateJob{}, false
	}
	return j, true
}
func (s *Server) startClientUpdate(w http.ResponseWriter, r *http.Request) {
	j, ok := s.deviceJob(w, r)
	if !ok {
		return
	}
	if _, ok = s.approvedJob(j); !ok {
		s.problem(w, 409, "release_approval_unavailable")
		return
	}
	if err := s.store.ChangeClientUpdateJob(r.Context(), j.ID, j.ClientID, clientupdate.JobDispatched, false, "", remoteIP(r), time.Now()); err != nil {
		s.problem(w, 409, "update_not_executable")
		return
	}
	w.WriteHeader(204)
}
func (s *Server) finishClientUpdate(w http.ResponseWriter, r *http.Request) {
	j, ok := s.deviceJob(w, r)
	if !ok {
		return
	}
	var result struct {
		State             clientupdate.JobState `json:"state"`
		RollbackAvailable bool                  `json:"rollback_available"`
	}
	if validation.DecodeJSON(w, r, &result, 1024) != nil || result.State != clientupdate.JobSucceeded && result.State != clientupdate.JobFailed {
		s.problem(w, 400, "invalid_update_result")
		return
	}
	if err := s.store.ChangeClientUpdateJob(r.Context(), j.ID, j.ClientID, result.State, result.RollbackAvailable, "", remoteIP(r), time.Now()); err != nil {
		s.problem(w, 409, "update_result_conflict")
		return
	}
	w.WriteHeader(204)
}
func (s *Server) downloadClientUpdate(w http.ResponseWriter, r *http.Request) {
	j, ok := s.deviceJob(w, r)
	if !ok {
		return
	}
	release, ok := s.approvedJob(j)
	if !ok || j.State != clientupdate.JobScheduled && j.State != clientupdate.JobDispatched || time.Now().Unix() >= j.ExpiresAt {
		s.problem(w, 409, "package_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "update.zip", time.Time{}, bytes.NewReader(release.Package))
}

var clientUpdateJobsTemplate = template.Must(template.New("client-updates").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Client updates — StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="content"><header class="topbar"><h1>Client updates</h1></header><section class="panel"><h2>Schedule an approved update</h2><p>Times use UTC with an explicit timezone, for example 2026-12-01T20:00:00Z. Offline clients wait until reconnect and never start outside the execution window. Only one open job is allowed per client.</p>{{if not .Enabled}}<p>Update execution is disabled. Configure an approved release catalog to enable it.</p>{{else if .CanWrite}}<form method="post" action="/client-updates"><input type="hidden" name="_csrf" value="{{.CSRF}}"><input type="hidden" name="id" value="{{.RequestID}}"><label>Client<select name="client_id" required>{{range .Clients}}<option>{{.ClientID}}</option>{{end}}</select></label><label>Approved release<select name="release_id" required>{{range .Releases}}<option value="{{.ID}}">{{.Manifest.ReleaseVersion}} · {{.Manifest.Architecture}}{{if .RequiresMaintenance}} · LightDM maintenance required{{end}}</option>{{end}}</select></label><label>Earliest start (UTC)<input name="not_before" placeholder="2026-12-01T20:00:00Z" required></label><label>Latest start (UTC)<input name="expires_at" placeholder="2026-12-01T21:00:00Z" required></label><label><input type="checkbox" name="maintenance" value="confirmed">I authorize LightDM restarts within this maintenance window</label><button type="submit">Schedule update</button></form>{{else}}<p>Read-only view.</p>{{end}}</section><section class="panel"><h2>Update jobs</h2><p>Dispatched jobs await the client's durable result. They are never automatically executed again. Rollback availability is reported after installation or recovery.</p><div class="table-wrap"><table><thead><tr><th>Client / job</th><th>Release</th><th>Execution window (UTC)</th><th>State</th><th>Rollback</th><th>Action</th></tr></thead><tbody>{{range .Jobs}}<tr><td>{{.ClientID}}<br><small class="mono">{{.ID}}</small></td><td>{{.ReleaseVersion}}</td><td>{{.Start}}<br>{{.End}}{{if .Maintenance}}<br>LightDM maintenance authorized{{end}}</td><td>{{.DisplayState}}</td><td>{{if .RollbackAvailable}}Available on client{{else}}Not reported{{end}}</td><td>{{if and $.CanWrite .Cancelable}}<form method="post" action="/client-updates/{{.ID}}/cancel"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="danger small">Cancel before execution</button></form>{{end}}</td></tr>{{else}}<tr><td colspan="6">No update jobs.</td></tr>{{end}}</tbody></table></div></section></main></body></html>`))
