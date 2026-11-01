package server

import (
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
)

const certificateExpiryWarning = 30 * 24 * time.Hour

type clientCertificateView struct {
	ClientID          string `json:"client_id"`
	Enabled           bool   `json:"enabled"`
	Version           string `json:"version"`
	AuthMode          string `json:"auth_mode"`
	AuthLabel         string `json:"auth_label"`
	TokenPolicy       string `json:"token_policy"`
	CertificateStatus string `json:"certificate_status"`
	CertificateLabel  string `json:"certificate_label"`
	ExpiresAt         string `json:"expires_at"`
	RemainingSeconds  *int64 `json:"remaining_seconds,omitempty"`
	PendingActivation bool   `json:"pending_activation"`
	Attention         string `json:"attention,omitempty"`
	Class             string `json:"-"`
}

func certificateClientView(c database.Client, m database.ClientCertificateSummary, now time.Time) clientCertificateView {
	v := clientCertificateView{ClientID: c.ClientID, Enabled: c.Enabled, Version: c.Version, AuthMode: c.AuthMode, CertificateStatus: "none", CertificateLabel: "No certificate", ExpiresAt: "—", Class: "neutral", PendingActivation: m.PendingActivation}
	switch c.AuthMode {
	case database.ClientAuthTokenOnly:
		v.AuthLabel = "Token only"
		v.TokenPolicy = "Bearer token accepted; certificate authentication disabled"
	case database.ClientAuthCertificatePreferred:
		v.AuthLabel = "Certificate preferred"
		v.TokenPolicy = "Certificate preferred; controlled bearer fallback allowed"
	case database.ClientAuthCertificateRequired:
		v.AuthLabel = "Certificate required"
		v.TokenPolicy = "Valid active certificate required; bearer token rejected"
	default:
		v.AuthLabel = "Unknown mode"
		v.TokenPolicy = "Authentication policy unavailable"
		v.Attention = "Unknown authentication mode"
		v.Class = "danger-text"
	}
	if m.ExpiresAt.Valid {
		v.ExpiresAt = m.ExpiresAt.Time.UTC().Format(time.RFC3339)
		remaining := int64(m.ExpiresAt.Time.Sub(now) / time.Second)
		v.RemainingSeconds = &remaining
	}
	switch m.Status {
	case "active":
		switch {
		case !m.IssuedAt.Valid || !m.ExpiresAt.Valid:
			v.CertificateStatus = "invalid"
			v.CertificateLabel = "Invalid certificate metadata"
			v.Class = "danger-text"
		case now.Before(m.IssuedAt.Time):
			v.CertificateStatus = "not_yet_valid"
			v.CertificateLabel = "Not yet valid"
			v.Class = "danger-text"
		case !now.Before(m.ExpiresAt.Time):
			v.CertificateStatus = "expired"
			v.CertificateLabel = "Expired"
			v.Class = "danger-text"
		case m.ExpiresAt.Time.Sub(now) <= certificateExpiryWarning:
			v.CertificateStatus = "expiring"
			v.CertificateLabel = "Expires within 30 days"
			v.Class = "warning"
		default:
			v.CertificateStatus = "valid"
			v.CertificateLabel = "Valid active certificate"
			v.Class = "success"
		}
	case "pending":
		v.CertificateStatus = "pending"
		v.CertificateLabel = "Pending activation"
		v.Class = "warning"
		if !m.CreatedAt.Valid || !now.Before(m.CreatedAt.Time.Add(database.ClientDeviceActivationWindow)) || !m.ExpiresAt.Valid || !now.Before(m.ExpiresAt.Time) {
			v.CertificateStatus = "activation_expired"
			v.CertificateLabel = "Activation window expired"
			v.Class = "danger-text"
		}
	case "revoked":
		v.CertificateStatus = "revoked"
		v.CertificateLabel = "Revoked"
		v.Class = "danger-text"
	case "superseded":
		v.CertificateStatus = "superseded"
		v.CertificateLabel = "Superseded; no active certificate"
		v.Class = "warning"
	case "":
	default:
		v.CertificateStatus = "unknown"
		v.CertificateLabel = "Unknown certificate state"
		v.Class = "danger-text"
	}
	usable := v.CertificateStatus == "valid" || v.CertificateStatus == "expiring"
	if c.AuthMode == database.ClientAuthCertificateRequired && !usable {
		v.Attention = "Certificate authentication unavailable; bearer fallback is rejected"
	}
	if c.AuthMode == database.ClientAuthCertificatePreferred && !usable {
		v.Attention = "No usable active certificate; controlled bearer fallback remains allowed"
	}
	if !c.Enabled {
		v.Attention = "Client disabled; device API authentication is blocked"
	}
	return v
}

func (s *Server) clientCertificateViews(ctx context.Context, now time.Time) ([]clientCertificateView, error) {
	clients, err := s.store.Clients(ctx)
	if err != nil {
		return nil, err
	}
	summaries, err := s.store.ClientCertificateSummaries(ctx, now)
	if err != nil {
		return nil, err
	}
	byClient := make(map[string]database.ClientCertificateSummary, len(summaries))
	for _, m := range summaries {
		byClient[m.ClientID] = m
	}
	views := make([]clientCertificateView, 0, len(clients))
	for _, c := range clients {
		views = append(views, certificateClientView(c, byClient[c.ClientID], now))
	}
	return views, nil
}
func (s *Server) clientCertificatesAPI(w http.ResponseWriter, r *http.Request) {
	views, err := s.clientCertificateViews(r.Context(), time.Now())
	if err != nil {
		s.problem(w, 503, "client_certificates_unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.json(w, 200, views)
}
func (s *Server) clientCertificatesPage(w http.ResponseWriter, r *http.Request) {
	views, err := s.clientCertificateViews(r.Context(), time.Now())
	if err != nil {
		s.problem(w, 503, "client_certificates_unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err = s.renderCompactAdminPage(w, r, clientCertificatesTemplate, map[string]any{"Clients": views}, "/clients"); err != nil {
		s.log.Error("client certificate template failed")
	}
}

var clientCertificatesTemplate = template.Must(template.New("client-certificates").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Clients — StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="content"><header class="topbar"><h1>Clients</h1><a class="button secondary" href="/client-updates">Client updates</a></header><section class="panel"><h2>Device authentication</h2><p>Read-only certificate metadata and configured authentication policy. Expiry times are UTC; certificates expiring within 30 days need renewal. A pending renewal does not replace the active certificate until activation succeeds. This page does not identify the transport used by the last status report.</p><div class="table-wrap"><table><thead><tr><th>Client</th><th>Authentication mode</th><th>Certificate</th><th>Expires (UTC)</th><th>Attention</th></tr></thead><tbody>{{range .Clients}}<tr><td><strong>{{.ClientID}}</strong><br>{{if .Enabled}}Enabled{{else}}Disabled{{end}} · {{.Version}}</td><td>{{.AuthLabel}}<br><small>{{.TokenPolicy}}</small></td><td><span class="badge {{.Class}}">{{.CertificateLabel}}</span>{{if .PendingActivation}}<br>Activation pending{{end}}</td><td>{{.ExpiresAt}}</td><td>{{.Attention}}</td></tr>{{else}}<tr><td colspan="5">No clients registered.</td></tr>{{end}}</tbody></table></div></section></main></body></html>`))
