package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/badge"
	"github.com/TheRealHZL/stumpfworks-identity/internal/database"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
	oidcprovider "github.com/TheRealHZL/stumpfworks-identity/internal/oidc"
	userpin "github.com/TheRealHZL/stumpfworks-identity/internal/pin"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
	"github.com/skip2/go-qrcode"
)

type Server struct {
	store               database.ApplicationStore
	log                 *slog.Logger
	started             time.Time
	mux                 *http.ServeMux
	dir                 directory.Directory
	sessions            *adminauth.Sessions
	protect             bool
	loginMu             sync.Mutex
	loginAttempts       map[string][]time.Time
	pinAttempts         map[string][]time.Time
	grantMu             sync.Mutex
	grants              map[string]loginGrant
	pkinit              *PKINITIssuer
	clientTargetVersion string
}
type loginGrant struct {
	Username, ClientID string
	Expires            time.Time
}
type AuthRequest struct {
	BadgeID  string `json:"badge_id"`
	Token    string `json:"token"`
	ClientID string `json:"client_id"`
	PIN      string `json:"pin,omitempty"`
}
type AuthResponse struct {
	Valid       bool   `json:"valid"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	BadgeID     string `json:"badge_id,omitempty"`
	Reason      string `json:"reason,omitempty"`
	LoginGrant  string `json:"login_grant,omitempty"`
}
type selfServiceBadgeView struct {
	ID                                        int64
	BadgeCode, Description, Created, LastUsed string
}
type selfServiceAuthView struct {
	BadgeCode, ClientID, Timestamp, Result string
	Success                                bool
}
type selfServiceSessionView struct {
	Created, Expires string
	Current          bool
}

func New(st database.ApplicationStore, l *slog.Logger) *Server {
	s := &Server{store: st, log: l, started: time.Now(), mux: http.NewServeMux(), loginAttempts: map[string][]time.Time{}, pinAttempts: map[string][]time.Time{}, grants: map[string]loginGrant{}, clientTargetVersion: version.Version}
	s.routes()
	return s
}

// audit records a security-relevant event without exposing database details to
// the request or logs. Existing handlers retain their current best-effort
// behaviour until mutations and their success events can be made atomic.
func (s *Server) audit(ctx context.Context, event, badge, user, client string, success bool, ip, details string) {
	if err := s.store.WriteAudit(ctx, database.Audit{EventType: event, BadgeID: badge, Username: user, ClientID: client, Success: success, IPAddress: ip, Details: details}); err != nil {
		s.log.Error("security audit write failed", "component", "audit", "event_type", event)
	}
}
func (s *Server) ConfigureClientTargetVersion(target string) error {
	if target == "" {
		s.clientTargetVersion = version.Version
		return nil
	}
	if _, ok := parseSemanticVersion(target); !ok {
		return errors.New("invalid client target version")
	}
	s.clientTargetVersion = target
	return nil
}
func (s *Server) ConfigureOIDC(provider *oidcprovider.Provider) { provider.Register(s.mux) }
func NewProtected(st database.ApplicationStore, l *slog.Logger, d directory.Directory, sessions *adminauth.Sessions) *Server {
	s := New(st, l)
	s.dir = d
	s.sessions = sessions
	s.protect = true
	return s
}
func (s *Server) Handler() http.Handler { return s.security(s.adminGuard(s.mux)) }
func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) { s.json(w, 200, map[string]string{"status": "ok"}) })
	s.mux.HandleFunc("POST /api/v1/client/status", s.clientStatus)
	s.mux.HandleFunc("GET /api/v1/clients", s.clients)
	s.mux.HandleFunc("GET /status", s.systemStatusPage)
	s.mux.HandleFunc("GET /api/v1/users", s.users)
	s.mux.HandleFunc("POST /api/v1/users", s.users)
	s.mux.HandleFunc("GET /api/v1/users/{id}", s.user)
	s.mux.HandleFunc("GET /api/v1/badges", s.badges)
	s.mux.HandleFunc("POST /api/v1/badges", s.badges)
	s.mux.HandleFunc("GET /api/v1/badges/{id}", s.badge)
	s.mux.HandleFunc("POST /api/v1/badges/{id}/revoke", s.revoke)
	s.mux.HandleFunc("POST /api/v1/badges/{id}/replace", s.replace)
	s.mux.HandleFunc("GET /api/v1/badges/{id}/qr", s.qr)
	s.mux.HandleFunc("POST /api/v1/auth/badge", s.auth)
	s.mux.HandleFunc("POST /api/v1/auth/pkinit", s.issuePKINIT)
	s.mux.HandleFunc("GET /api/v1/directory/users", s.directoryUsers)
	s.mux.HandleFunc("POST /directory/users/import", s.importDirectoryUser)
	s.mux.HandleFunc("POST /users/{id}/pin", s.setUserPIN)
	s.mux.HandleFunc("GET /pin", s.pinPage)
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.login)
	s.mux.HandleFunc("POST /logout", s.logout)
	s.mux.HandleFunc("GET /self-service", s.selfServicePage)
	s.mux.HandleFunc("POST /self-service/login", s.selfServiceLogin)
	s.mux.HandleFunc("POST /self-service/pin", s.selfServiceSetPIN)
	s.mux.HandleFunc("POST /self-service/badges/{id}/revoke", s.selfServiceRevokeBadge)
	s.mux.HandleFunc("POST /self-service/badges/activate", s.selfServiceActivateBadge)
	s.mux.HandleFunc("POST /self-service/sessions/logout-others", s.selfServiceLogoutOthers)
	s.mux.HandleFunc("POST /self-service/logout", s.selfServiceLogout)
	s.mux.HandleFunc("GET /static/style.css", style)
	s.mux.HandleFunc("GET /", s.web)
	s.mux.HandleFunc("POST /users", s.webCreateUser)
	s.mux.HandleFunc("POST /badges", s.webCreateBadge)
	s.mux.HandleFunc("POST /badges/{id}/revoke", s.webRevoke)
	s.mux.HandleFunc("POST /badges/{id}/replace", s.webReplace)
}
func (s *Server) adminGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.protect || r.URL.Path == "/login" || r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/client/status" || r.URL.Path == "/api/v1/auth/badge" || r.URL.Path == "/api/v1/auth/pkinit" || r.URL.Path == "/.well-known/openid-configuration" || strings.HasPrefix(r.URL.Path, "/oauth2/") || strings.HasPrefix(r.URL.Path, "/self-service") || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		c, e := r.Cookie("swbadge_admin")
		if e == nil {
			if _, e = s.sessions.Verify(c.Value, time.Now()); e == nil {
				if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
					_ = r.ParseForm()
					token := r.FormValue("_csrf")
					if token == "" {
						token = r.Header.Get("X-CSRF-Token")
					}
					if !s.sessions.VerifyCSRF(c.Value, token) {
						s.problem(w, http.StatusForbidden, "csrf_invalid")
						return
					}
				}
				next.ServeHTTP(w, r)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			s.problem(w, http.StatusUnauthorized, "authentication_required")
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}
func (s *Server) loginAllowed(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	cut := time.Now().Add(-10 * time.Minute)
	recent := s.loginAttempts[ip][:0]
	for _, t := range s.loginAttempts[ip] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	s.loginAttempts[ip] = recent
	return len(recent) < 5
}
func (s *Server) loginFailed(ip string) {
	s.loginMu.Lock()
	s.loginAttempts[ip] = append(s.loginAttempts[ip], time.Now())
	s.loginMu.Unlock()
}
func (s *Server) loginSucceeded(ip string) {
	s.loginMu.Lock()
	delete(s.loginAttempts, ip)
	s.loginMu.Unlock()
}
func (s *Server) pinAllowed(key string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	cut := time.Now().Add(-10 * time.Minute)
	recent := s.pinAttempts[key][:0]
	for _, t := range s.pinAttempts[key] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	s.pinAttempts[key] = recent
	return len(recent) < 5
}
func (s *Server) pinFailed(key string) {
	s.loginMu.Lock()
	s.pinAttempts[key] = append(s.pinAttempts[key], time.Now())
	s.loginMu.Unlock()
}
func (s *Server) pinSucceeded(key string) {
	s.loginMu.Lock()
	delete(s.pinAttempts, key)
	s.loginMu.Unlock()
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.protect {
		http.Redirect(w, r, "/", 303)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, loginTemplate)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.protect {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	ip := remoteIP(r)
	if !s.loginAllowed(ip) {
		s.problem(w, http.StatusTooManyRequests, "login_rate_limited")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	u, e := s.dir.AuthenticateAdmin(r.Context(), username, r.FormValue("password"))
	if e != nil {
		s.loginFailed(ip)
		s.log.Warn("admin login denied", "event", "admin_login_failed", "username", username, "ip_address", remoteIP(r))
		http.Redirect(w, r, "/login?error=1", 303)
		return
	}
	s.loginSucceeded(ip)
	token := s.sessions.Issue(u.Username, time.Now())
	http.SetCookie(w, &http.Cookie{Name: "swbadge_admin", Value: token, Path: "/", MaxAge: 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	s.log.Info("admin login accepted", "event", "admin_login_success", "username", u.Username, "ip_address", remoteIP(r))
	s.audit(r.Context(), "admin_login", "", u.Username, "", true, ip, "")
	http.Redirect(w, r, "/", 303)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "swbadge_admin", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", 303)
}
func (s *Server) directoryUsers(w http.ResponseWriter, r *http.Request) {
	if s.dir == nil {
		s.problem(w, 503, "directory_disabled")
		return
	}
	users, e := s.dir.ListUsers(r.Context())
	if e != nil {
		s.log.Error("directory listing failed", "error", e)
		s.problem(w, 502, "directory_unavailable")
		return
	}
	s.json(w, 200, users)
}
func (s *Server) importDirectoryUser(w http.ResponseWriter, r *http.Request) {
	if s.dir == nil {
		s.problem(w, 503, "directory_disabled")
		return
	}
	u, e := s.dir.GetUser(r.Context(), strings.TrimSpace(r.FormValue("username")))
	if e != nil {
		s.problem(w, 404, "directory_user_not_found")
		return
	}
	created, e := s.store.CreateUser(r.Context(), u.Username, u.DisplayName, u.DN)
	if e != nil {
		http.Redirect(w, r, "/users?status=already_imported", 303)
		return
	}
	s.audit(r.Context(), "directory_user_imported", "", created.Username, "", true, remoteIP(r), "")
	http.Redirect(w, r, "/users?status=imported", 303)
}
func (s *Server) setUserPIN(w http.ResponseWriter, r *http.Request) {
	n, e := id(r)
	if e != nil {
		s.problem(w, 400, "invalid_id")
		return
	}
	u, e := s.store.GetUser(r.Context(), n)
	if e != nil {
		s.problem(w, 404, "user_unknown")
		return
	}
	value := r.FormValue("pin")
	hash := ""
	event := "pin_disabled"
	if value != "" {
		hash, e = userpin.Hash(value)
		event = "pin_enabled"
		if e != nil {
			s.problem(w, 400, "invalid_pin")
			return
		}
	}
	if e = s.store.SetUserPIN(r.Context(), n, hash); e != nil {
		s.problem(w, 500, "database_error")
		return
	}
	s.audit(r.Context(), event, "", u.Username, "", true, remoteIP(r), "")
	http.Redirect(w, r, "/users", 303)
}
func (s *Server) pinPage(w http.ResponseWriter, r *http.Request) {
	users, e := s.store.Users(r.Context())
	if e != nil {
		s.problem(w, 500, "database_error")
		return
	}
	c, _ := r.Cookie("swbadge_admin")
	data := map[string]any{"Users": users, "CSRF": s.sessions.CSRF(c.Value)}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = template.Must(template.New("pin").Parse(pinTemplate)).Execute(w, data)
}
func (s *Server) selfServiceSession(r *http.Request) (string, string, string, bool) {
	if !s.protect || s.sessions == nil {
		return "", "", "", false
	}
	c, e := r.Cookie("swbadge_selfservice")
	if e != nil {
		return "", "", "", false
	}
	identity, e := s.sessions.VerifyFor(c.Value, "self-service", time.Now())
	parts := strings.Split(identity, "\x1f")
	if e != nil || len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	if _, e = s.store.ActiveSelfServiceSession(r.Context(), parts[1], parts[0], time.Now()); e != nil {
		return "", "", "", false
	}
	return parts[0], parts[1], c.Value, true
}
func (s *Server) selfServicePage(w http.ResponseWriter, r *http.Request) {
	if !s.protect || s.dir == nil || s.sessions == nil {
		http.Error(w, "Self-service is unavailable", http.StatusServiceUnavailable)
		return
	}
	data := map[string]any{"Error": r.URL.Query().Get("error"), "Status": r.URL.Query().Get("status")}
	if username, sessionID, token, ok := s.selfServiceSession(r); ok {
		if u, e := s.store.UserByUsername(r.Context(), username); e == nil {
			badges, badgeErr := s.store.ActiveBadgesByUser(r.Context(), u.ID)
			authEvents, authErr := s.store.RecentBadgeAuthByUser(r.Context(), u.Username)
			sessions, sessionErr := s.store.ActiveSelfServiceSessions(r.Context(), u.Username, time.Now())
			if badgeErr == nil && authErr == nil && sessionErr == nil {
				views := make([]selfServiceBadgeView, 0, len(badges))
				for _, b := range badges {
					lastUsed := "Never"
					if b.LastUsedAt.Valid {
						lastUsed = b.LastUsedAt.Time.Format("02 Jan 2006, 15:04")
					}
					views = append(views, selfServiceBadgeView{ID: b.ID, BadgeCode: b.BadgeCode, Description: b.Description, Created: b.CreatedAt.Format("02 Jan 2006"), LastUsed: lastUsed})
				}
				authViews := make([]selfServiceAuthView, 0, len(authEvents))
				for _, event := range authEvents {
					result := "Denied"
					if event.Success {
						result = "Successful"
					}
					authViews = append(authViews, selfServiceAuthView{BadgeCode: event.BadgeID, ClientID: event.ClientID, Timestamp: event.Timestamp.UTC().Format("02 Jan 2006, 15:04 UTC"), Result: result, Success: event.Success})
				}
				data["Authenticated"] = true
				data["User"] = u
				data["Badges"] = views
				data["AuthEvents"] = authViews
				sessionViews := make([]selfServiceSessionView, 0, len(sessions))
				for _, session := range sessions {
					sessionViews = append(sessionViews, selfServiceSessionView{Created: session.CreatedAt.UTC().Format("02 Jan 2006, 15:04 UTC"), Expires: session.ExpiresAt.UTC().Format("15:04 UTC"), Current: session.ID == sessionID})
				}
				data["Sessions"] = sessionViews
				data["CSRF"] = s.sessions.CSRF(token)
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = template.Must(template.New("self-service").Parse(selfServicePageTemplate())).Execute(w, data)
}

func selfServicePageTemplate() string {
	const pinForm = `<form class="login-form" method="post" action="/self-service/pin">`
	return strings.Replace(selfServiceTemplate, pinForm, selfServiceExtraTemplate+pinForm, 1)
}
func (s *Server) selfServiceLogin(w http.ResponseWriter, r *http.Request) {
	if !s.protect || s.dir == nil || s.sessions == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	_ = r.ParseForm()
	ip := remoteIP(r)
	if !s.loginAllowed("self-service:" + ip) {
		http.Redirect(w, r, "/self-service?error=rate_limited", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	u, e := s.dir.AuthenticateUser(r.Context(), username, r.FormValue("password"))
	if e != nil {
		s.loginFailed("self-service:" + ip)
		s.log.Warn("self-service login denied", "event", "self_service_login_failed", "username", username, "ip_address", ip)
		s.audit(r.Context(), "self_service_login", "", username, "", false, ip, "")
		http.Redirect(w, r, "/self-service?error=invalid_credentials", http.StatusSeeOther)
		return
	}
	s.loginSucceeded("self-service:" + ip)
	local, e := s.store.UserByUsername(r.Context(), u.Username)
	if errors.Is(e, sql.ErrNoRows) {
		local, e = s.store.CreateUser(r.Context(), u.Username, u.DisplayName, u.DN)
	}
	if e != nil {
		s.log.Error("self-service user provisioning failed", "username", u.Username, "error", e)
		http.Redirect(w, r, "/self-service?error=unavailable", http.StatusSeeOther)
		return
	}
	sessionID, e := badge.GenerateToken()
	if e != nil {
		http.Redirect(w, r, "/self-service?error=unavailable", http.StatusSeeOther)
		return
	}
	expiresAt := time.Now().Add(15 * time.Minute)
	if e = s.store.CreateSelfServiceSession(r.Context(), sessionID, local.Username, expiresAt); e != nil {
		http.Redirect(w, r, "/self-service?error=unavailable", http.StatusSeeOther)
		return
	}
	token := s.sessions.IssueForDuration("self-service", local.Username+"\x1f"+sessionID, time.Now(), 15*time.Minute)
	http.SetCookie(w, &http.Cookie{Name: "swbadge_selfservice", Value: token, Path: "/self-service", MaxAge: 900, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	s.audit(r.Context(), "self_service_login", "", local.Username, "", true, ip, "")
	http.Redirect(w, r, "/self-service", http.StatusSeeOther)
}
func (s *Server) selfServiceSetPIN(w http.ResponseWriter, r *http.Request) {
	username, _, token, ok := s.selfServiceSession(r)
	if !ok {
		http.Redirect(w, r, "/self-service?error=session_expired", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	_ = r.ParseForm()
	if !s.sessions.VerifyCSRF(token, r.FormValue("_csrf")) {
		s.problem(w, http.StatusForbidden, "csrf_invalid")
		return
	}
	pinValue := r.FormValue("pin")
	if pinValue != r.FormValue("pin_confirm") || !validSelfServicePIN(pinValue) {
		http.Redirect(w, r, "/self-service?error=invalid_pin", http.StatusSeeOther)
		return
	}
	u, e := s.store.UserByUsername(r.Context(), username)
	if e != nil {
		http.Redirect(w, r, "/self-service?error=unavailable", http.StatusSeeOther)
		return
	}
	hash, e := userpin.Hash(pinValue)
	if e != nil || s.store.SetUserPIN(r.Context(), u.ID, hash) != nil {
		http.Redirect(w, r, "/self-service?error=unavailable", http.StatusSeeOther)
		return
	}
	s.audit(r.Context(), "pin_self_service_changed", "", u.Username, "", true, remoteIP(r), "")
	http.Redirect(w, r, "/self-service?status=pin_updated", http.StatusSeeOther)
}
func validSelfServicePIN(value string) bool {
	if len(value) < 4 || len(value) > 12 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func (s *Server) selfServiceRevokeBadge(w http.ResponseWriter, r *http.Request) {
	username, _, token, ok := s.selfServiceSession(r)
	if !ok {
		http.Redirect(w, r, "/self-service?error=session_expired", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	_ = r.ParseForm()
	if !s.sessions.VerifyCSRF(token, r.FormValue("_csrf")) {
		s.problem(w, http.StatusForbidden, "csrf_invalid")
		return
	}
	badgeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || badgeID < 1 {
		http.Redirect(w, r, "/self-service?error=badge_unavailable", http.StatusSeeOther)
		return
	}
	u, err := s.store.UserByUsername(r.Context(), username)
	if err != nil {
		http.Redirect(w, r, "/self-service?error=unavailable", http.StatusSeeOther)
		return
	}
	b, err := s.store.RevokeActiveBadgeForUser(r.Context(), badgeID, u.ID)
	if err != nil {
		http.Redirect(w, r, "/self-service?error=badge_unavailable", http.StatusSeeOther)
		return
	}
	s.audit(r.Context(), "badge_self_service_revoked", b.BadgeCode, u.Username, "", true, remoteIP(r), "lost_badge")
	http.Redirect(w, r, "/self-service?status=badge_revoked", http.StatusSeeOther)
}
func (s *Server) selfServiceActivateBadge(w http.ResponseWriter, r *http.Request) {
	username, _, sessionToken, ok := s.selfServiceSession(r)
	if !ok {
		http.Redirect(w, r, "/self-service?error=session_expired", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	_ = r.ParseForm()
	if !s.sessions.VerifyCSRF(sessionToken, r.FormValue("_csrf")) {
		s.problem(w, http.StatusForbidden, "csrf_invalid")
		return
	}
	code, token, err := badge.ParsePayload(strings.TrimSpace(r.FormValue("payload")))
	u, userErr := s.store.UserByUsername(r.Context(), username)
	b, badgeErr := s.store.BadgeByCode(r.Context(), code)
	if err != nil || userErr != nil || badgeErr != nil || b.UserID != u.ID || !b.ActivationPending || b.Enabled || !badge.VerifyToken(token, b.TokenHash) {
		http.Redirect(w, r, "/self-service?error=activation_invalid", http.StatusSeeOther)
		return
	}
	if err = s.store.ActivatePendingBadgeForUser(r.Context(), b.ID, u.ID); err != nil {
		http.Redirect(w, r, "/self-service?error=activation_invalid", http.StatusSeeOther)
		return
	}
	s.audit(r.Context(), "badge_self_service_activated", b.BadgeCode, u.Username, "", true, remoteIP(r), "replacement_badge")
	http.Redirect(w, r, "/self-service?status=badge_activated", http.StatusSeeOther)
}
func (s *Server) selfServiceLogoutOthers(w http.ResponseWriter, r *http.Request) {
	username, sessionID, token, ok := s.selfServiceSession(r)
	if !ok {
		http.Redirect(w, r, "/self-service?error=session_expired", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	_ = r.ParseForm()
	if !s.sessions.VerifyCSRF(token, r.FormValue("_csrf")) {
		s.problem(w, http.StatusForbidden, "csrf_invalid")
		return
	}
	count, err := s.store.RevokeOtherSelfServiceSessions(r.Context(), username, sessionID)
	if err != nil {
		http.Redirect(w, r, "/self-service?error=unavailable", http.StatusSeeOther)
		return
	}
	s.audit(r.Context(), "self_service_sessions_revoked", "", username, "", true, remoteIP(r), fmt.Sprintf("count=%d", count))
	http.Redirect(w, r, "/self-service?status=sessions_revoked", http.StatusSeeOther)
}
func (s *Server) selfServiceLogout(w http.ResponseWriter, r *http.Request) {
	if username, sessionID, token, ok := s.selfServiceSession(r); ok {
		_ = r.ParseForm()
		if !s.sessions.VerifyCSRF(token, r.FormValue("_csrf")) {
			s.problem(w, http.StatusForbidden, "csrf_invalid")
			return
		}
		_ = s.store.RevokeSelfServiceSession(r.Context(), sessionID, username)
	}
	http.SetCookie(w, &http.Cookie{Name: "swbadge_selfservice", Value: "", Path: "/self-service", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/self-service", http.StatusSeeOther)
}
func (s *Server) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}
func id(r *http.Request) (int64, error) { return strconv.ParseInt(r.PathValue("id"), 10, 64) }
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		v, e := s.store.Users(r.Context())
		if e != nil {
			s.problem(w, 500, "database_error")
			return
		}
		s.json(w, 200, v)
		return
	}
	var in struct{ Username, DisplayName, DirectoryDN string }
	if decode(w, r, &in) != nil || strings.TrimSpace(in.Username) == "" {
		s.problem(w, 400, "invalid_request")
		return
	}
	if in.DisplayName == "" {
		in.DisplayName = in.Username
	}
	u, e := s.store.CreateUser(r.Context(), in.Username, in.DisplayName, in.DirectoryDN)
	if e != nil {
		s.problem(w, 409, "user_exists")
		return
	}
	s.audit(r.Context(), "user_created", "", u.Username, "", true, remoteIP(r), "")
	s.json(w, 201, u)
}
func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	n, e := id(r)
	if e != nil {
		s.problem(w, 400, "invalid_id")
		return
	}
	u, e := s.store.GetUser(r.Context(), n)
	if errors.Is(e, sql.ErrNoRows) {
		s.problem(w, 404, "user_unknown")
		return
	}
	if e != nil {
		s.problem(w, 500, "database_error")
		return
	}
	s.json(w, 200, u)
}
func (s *Server) badges(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		v, e := s.store.Badges(r.Context())
		if e != nil {
			s.problem(w, 500, "database_error")
			return
		}
		s.json(w, 200, v)
		return
	}
	var in struct {
		UserID      int64  `json:"user_id"`
		Description string `json:"description"`
	}
	if decode(w, r, &in) != nil || in.UserID < 1 {
		s.problem(w, 400, "invalid_request")
		return
	}
	b, t, e := s.createBadge(r, in.UserID, in.Description)
	if e != nil {
		s.problem(w, 400, "user_unknown")
		return
	}
	s.json(w, 201, map[string]any{"badge": b, "payload": badge.Payload(b.BadgeCode, t), "token_notice": "This secret is shown once and is not stored."})
}
func (s *Server) createBadge(r *http.Request, user int64, desc string) (database.Badge, string, error) {
	u, e := s.store.GetUser(r.Context(), user)
	if e != nil {
		return database.Badge{}, "", e
	}
	if s.dir != nil {
		exists, e := s.dir.UserExists(r.Context(), u.Username)
		if e != nil || !exists {
			return database.Badge{}, "", directory.ErrUserNotFound
		}
	}
	t, e := badge.GenerateToken()
	if e != nil {
		return database.Badge{}, "", e
	}
	b, e := s.store.CreateBadge(r.Context(), user, badge.HashToken(t), desc)
	if e == nil {
		s.audit(r.Context(), "badge_created", b.BadgeCode, b.Username, "", true, remoteIP(r), "")
	}
	return b, t, e
}
func (s *Server) badge(w http.ResponseWriter, r *http.Request) {
	n, e := id(r)
	if e != nil {
		s.problem(w, 400, "invalid_id")
		return
	}
	b, e := s.store.GetBadge(r.Context(), n)
	if errors.Is(e, sql.ErrNoRows) {
		s.problem(w, 404, "badge_unknown")
		return
	}
	if e != nil {
		s.problem(w, 500, "database_error")
		return
	}
	s.json(w, 200, b)
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	n, e := id(r)
	if e != nil {
		s.problem(w, 400, "invalid_id")
		return
	}
	b, e := s.store.GetBadge(r.Context(), n)
	if e != nil {
		s.problem(w, 404, "badge_unknown")
		return
	}
	if e = s.store.Revoke(r.Context(), n); e != nil {
		s.problem(w, 500, "database_error")
		return
	}
	s.audit(r.Context(), "badge_revoked", b.BadgeCode, b.Username, "", true, remoteIP(r), "")
	w.WriteHeader(204)
}
func (s *Server) replace(w http.ResponseWriter, r *http.Request) {
	n, e := id(r)
	if e != nil {
		s.problem(w, 400, "invalid_id")
		return
	}
	old, e := s.store.GetBadge(r.Context(), n)
	if e != nil {
		s.problem(w, 404, "badge_unknown")
		return
	}
	t, e := badge.GenerateToken()
	if e != nil {
		s.problem(w, 500, "token_generation_failed")
		return
	}
	b, e := s.store.ReplaceBadgePending(r.Context(), n, badge.HashToken(t), "Replacement for "+old.BadgeCode)
	if e != nil {
		s.problem(w, 500, "database_error")
		return
	}
	s.audit(r.Context(), "badge_replaced", old.BadgeCode, old.Username, "", true, remoteIP(r), "new_badge="+b.BadgeCode)
	s.json(w, 201, map[string]any{"badge": b, "payload": badge.Payload(b.BadgeCode, t), "activation_notice": "The replacement remains disabled until its owner activates this one-time payload in self-service.", "token_notice": "This secret is shown once and is not stored."})
}
func (s *Server) qr(w http.ResponseWriter, r *http.Request) {
	payload := r.URL.Query().Get("payload")
	c, _, e := badge.ParsePayload(payload)
	n, ie := id(r)
	if e != nil || ie != nil {
		s.problem(w, 400, "invalid_payload")
		return
	}
	b, e := s.store.GetBadge(r.Context(), n)
	if e != nil || b.BadgeCode != c {
		s.problem(w, 404, "badge_unknown")
		return
	}
	png, e := qrcode.Encode(payload, qrcode.Medium, 320)
	if e != nil {
		s.problem(w, 500, "qrcode_error")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}
func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	var in AuthRequest
	if decode(w, r, &in) != nil || in.BadgeID == "" || in.Token == "" || in.ClientID == "" {
		s.problem(w, 400, "invalid_request")
		return
	}
	ip := remoteIP(r)
	b, e := s.store.BadgeByCode(r.Context(), in.BadgeID)
	reason := ""
	pinKey := in.BadgeID + "|" + in.ClientID + "|" + ip
	if errors.Is(e, sql.ErrNoRows) {
		reason = "badge_unknown"
	} else if e != nil {
		reason = "database_error"
	} else if !b.Enabled {
		reason = "badge_disabled"
	} else if !badge.VerifyToken(in.Token, b.TokenHash) {
		reason = "invalid_token"
	} else if b.PINHash != "" && in.PIN == "" {
		reason = "pin_required"
	} else if b.PINHash != "" && !s.pinAllowed(pinKey) {
		reason = "pin_rate_limited"
	} else if b.PINHash != "" && !userpin.Verify(in.PIN, b.PINHash) {
		reason = "invalid_pin"
		s.pinFailed(pinKey)
	}
	if reason != "" {
		s.audit(r.Context(), "auth_failed", in.BadgeID, "", in.ClientID, false, ip, reason)
		s.log.Warn("badge authentication denied", "event", "auth_failed", "badge_id", in.BadgeID, "client_id", in.ClientID, "reason", reason)
		s.json(w, 200, AuthResponse{Valid: false, Reason: reason})
		return
	}
	_ = s.store.Used(r.Context(), b.ID)
	s.pinSucceeded(pinKey)
	s.audit(r.Context(), "auth_success", b.BadgeCode, b.Username, in.ClientID, true, ip, "")
	s.log.Info("badge authentication accepted", "event", "auth_success", "badge_id", b.BadgeCode, "client_id", in.ClientID, "username", b.Username)
	grant, e := s.newLoginGrant(b.Username, in.ClientID)
	if e != nil {
		s.problem(w, 500, "grant_error")
		return
	}
	s.json(w, 200, AuthResponse{Valid: true, Username: b.Username, DisplayName: b.DisplayName, BadgeID: b.BadgeCode, LoginGrant: grant})
}
func (s *Server) newLoginGrant(username, clientID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	s.grantMu.Lock()
	now := time.Now()
	for k, v := range s.grants {
		if !v.Expires.After(now) {
			delete(s.grants, k)
		}
	}
	s.grants[token] = loginGrant{Username: username, ClientID: clientID, Expires: now.Add(30 * time.Second)}
	s.grantMu.Unlock()
	return token, nil
}
func (s *Server) redeemLoginGrant(token, clientID string) (loginGrant, bool) {
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	g, ok := s.grants[token]
	delete(s.grants, token)
	return g, ok && g.ClientID == clientID && g.Expires.After(time.Now())
}
func (s *Server) problem(w http.ResponseWriter, status int, reason string) {
	s.json(w, status, map[string]any{"valid": false, "reason": reason})
}
func remoteIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return h
	}
	return r.RemoteAddr
}
func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

var page = template.Must(template.New("page").Parse(webPageTemplate()))

func webPageTemplate() string {
	result := strings.Replace(webTemplate, `{{if .Enabled}}<span class="badge success">Active</span>{{else}}<span class="badge neutral">Revoked</span>{{end}}`, `{{if .Enabled}}<span class="badge success">Active</span>{{else if .ActivationPending}}<span class="badge warning">Pending activation</span>{{else}}<span class="badge neutral">Revoked</span>{{end}}`, 1)
	const revoke = `<form method="post" action="/badges/{{.ID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="danger small" type="submit">Revoke</button></form>`
	return strings.Replace(result, revoke, revoke+`<form method="post" action="/badges/{{.ID}}/replace"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="small" type="submit">Issue replacement</button></form>`, 1)
}

func (s *Server) web(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/users" && r.URL.Path != "/badges" && r.URL.Path != "/audit" && r.URL.Path != "/status" {
		http.NotFound(w, r)
		return
	}
	users, _ := s.store.Users(r.Context())
	badges, _ := s.store.Badges(r.Context())
	audits, _ := s.store.Audits(r.Context())
	var adUsers []directory.User
	if s.dir != nil && r.URL.Path == "/users" {
		adUsers, _ = s.dir.ListUsers(r.Context())
	}
	csrf := ""
	if c, e := r.Cookie("swbadge_admin"); e == nil && s.sessions != nil {
		csrf = s.sessions.CSRF(c.Value)
	}
	stats, err := s.store.Counts(r.Context())
	if err != nil {
		s.log.Error("database counts failed", "component", "database")
		stats = map[string]int64{}
	}
	data := map[string]any{"Path": r.URL.Path, "Users": users, "ADUsers": adUsers, "CSRF": csrf, "Badges": badges, "Audits": audits, "Stats": stats, "Version": version.Version, "Uptime": time.Since(s.started).Round(time.Second), "Payload": r.URL.Query().Get("payload")}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = page.Execute(w, data)
}
func (s *Server) webCreateUser(w http.ResponseWriter, r *http.Request) {
	if e := r.ParseForm(); e == nil {
		u := strings.TrimSpace(r.FormValue("username"))
		d := strings.TrimSpace(r.FormValue("display_name"))
		if d == "" {
			d = u
		}
		if u != "" {
			if x, e := s.store.CreateUser(r.Context(), u, d, ""); e == nil {
				s.audit(r.Context(), "user_created", "", x.Username, "", true, remoteIP(r), "")
			}
		}
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
func (s *Server) webCreateBadge(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	uid, _ := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	b, t, e := s.createBadge(r, uid, r.FormValue("description"))
	if e != nil {
		http.Redirect(w, r, "/badges", 303)
		return
	}
	http.Redirect(w, r, "/badges?payload="+badge.Payload(b.BadgeCode, t), 303)
}
func (s *Server) webRevoke(w http.ResponseWriter, r *http.Request) {
	n, _ := id(r)
	if b, e := s.store.GetBadge(r.Context(), n); e == nil {
		_ = s.store.Revoke(r.Context(), n)
		s.audit(r.Context(), "badge_revoked", b.BadgeCode, b.Username, "", true, remoteIP(r), "")
	}
	http.Redirect(w, r, "/badges", 303)
}
func (s *Server) webReplace(w http.ResponseWriter, r *http.Request) {
	n, err := id(r)
	old, getErr := s.store.GetBadge(r.Context(), n)
	if err != nil || getErr != nil || !old.Enabled {
		http.Redirect(w, r, "/badges", http.StatusSeeOther)
		return
	}
	token, err := badge.GenerateToken()
	if err != nil {
		http.Redirect(w, r, "/badges", http.StatusSeeOther)
		return
	}
	replacement, err := s.store.ReplaceBadgePending(r.Context(), old.ID, badge.HashToken(token), "Replacement for "+old.BadgeCode)
	if err != nil {
		http.Redirect(w, r, "/badges", http.StatusSeeOther)
		return
	}
	s.audit(r.Context(), "badge_replaced", old.BadgeCode, old.Username, "", true, remoteIP(r), "new_badge="+replacement.BadgeCode)
	http.Redirect(w, r, "/badges?payload="+badge.Payload(replacement.BadgeCode, token), http.StatusSeeOther)
}
func style(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	fmt.Fprint(w, css, selfServiceCSS, selfServiceHistoryCSS)
}

const selfServiceExtraTemplate = `{{if eq .Status "badge_activated"}}<div class="notice success-notice">Your replacement badge is active and ready to use.</div>{{else if eq .Status "sessions_revoked"}}<div class="notice success-notice">All other self-service sessions were signed out.</div>{{end}}{{if eq .Error "activation_invalid"}}<div class="notice error-notice">The replacement payload is invalid, unavailable or not assigned to your account.</div>{{end}}<section class="self-activation"><div class="self-section-head"><div><h2>Activate a replacement badge</h2><p>Paste the complete one-time payload issued by an administrator.</p></div></div><form class="activation-form" method="post" action="/self-service/badges/activate"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label><span>Replacement payload</span><input type="password" name="payload" autocomplete="off" placeholder="SWBADGE:1:…" required></label><button type="submit">Activate badge</button></form></section><section class="self-history"><div class="self-section-head"><div><h2>Recent badge sign-ins</h2><p>Your latest 20 badge authentication events. Network addresses are not shown.</p></div><span class="count">{{len .AuthEvents}}</span></div>{{range .AuthEvents}}<article class="self-history-row"><span><strong>{{if .BadgeCode}}{{.BadgeCode}}{{else}}Badge unavailable{{end}}</strong><small>{{.Timestamp}}</small></span><span><small>Client</small><strong>{{if .ClientID}}{{.ClientID}}{{else}}Unknown{{end}}</strong></span><span class="badge {{if .Success}}success{{else}}danger-text{{end}}">{{.Result}}</span></article>{{else}}<p class="self-empty">No badge sign-ins have been recorded for your account yet.</p>{{end}}</section><section class="self-sessions"><div class="self-section-head"><div><h2>My self-service sessions</h2><p>Sessions expire automatically after 15 minutes.</p></div><span class="count">{{len .Sessions}}</span></div>{{range .Sessions}}<article class="self-session-row"><span><strong>{{if .Current}}This browser{{else}}Other browser{{end}}</strong><small>Started {{.Created}} · expires {{.Expires}}</small></span>{{if .Current}}<span class="badge success">Current</span>{{else}}<span class="badge neutral">Active</span>{{end}}</article>{{end}}{{if gt (len .Sessions) 1}}<form method="post" action="/self-service/sessions/logout-others"><input type="hidden" name="_csrf" value="{{.CSRF}}"><button class="danger small" type="submit">Sign out all other sessions</button></form>{{end}}</section>`

const selfServiceHistoryCSS = `.self-history,.self-activation,.self-sessions{margin:22px 0;padding:18px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.018)}.self-history-row,.self-session-row{display:grid;grid-template-columns:1fr auto auto;align-items:center;gap:18px;padding:12px 0;border-top:1px solid var(--line)}.self-history-row strong,.self-history-row small,.self-session-row strong,.self-session-row small{display:block}.self-history-row small,.self-session-row small{color:var(--muted);font-size:10px}.activation-form{display:grid;grid-template-columns:1fr auto;align-items:end;gap:12px}.activation-form label span{display:block;color:var(--muted);font-size:11px;margin-bottom:6px}@media(max-width:680px){.self-history-row,.self-session-row,.activation-form{grid-template-columns:1fr}.self-history-row .badge,.self-session-row .badge{justify-self:start}}`

const webTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body><aside class="sidebar"><a class="brand" href="/"><span class="brand-mark">S</span><span><strong>StumpfWorks</strong><small>Identity Platform</small></span></a><nav aria-label="Main navigation"><a class="{{if eq .Path "/"}}active{{end}}" href="/"><span>◈</span>Dashboard</a><a class="{{if eq .Path "/users"}}active{{end}}" href="/users"><span>◎</span>Users</a><a class="{{if eq .Path "/badges"}}active{{end}}" href="/badges"><span>◇</span>Badges</a><a class="{{if eq .Path "/audit"}}active{{end}}" href="/audit"><span>≡</span>Audit log</a><a class="{{if eq .Path "/status"}}active{{end}}" href="/status"><span>◉</span>System status</a></nav><div class="sidebar-foot"><div class="server-state"><i></i><span><strong>LOGIN01</strong><small>Operational</small></span></div><form method="post" action="/logout"><input type="hidden" name="_csrf" value="{{.CSRF}}"><button class="ghost" type="submit">Sign out</button></form><small class="version">Identity v{{.Version}}</small></div></aside><main class="content"><header class="topbar"><div><p class="eyebrow">STUMPFWORKS / IDENTITY</p><h1>{{if eq .Path "/"}}Dashboard{{else if eq .Path "/users"}}Users{{else if eq .Path "/badges"}}Badges{{else if eq .Path "/audit"}}Audit log{{else}}System status{{end}}</h1></div><span class="status-chip"><i></i>All systems operational</span></header>{{if eq .Path "/"}}<section class="hero panel"><div><span class="kicker">Secure access, simplified</span><h2>Badge authentication gateway</h2><p>Manage short-lived physical credentials without storing Active Directory passwords.</p></div><div class="hero-icon">◇</div></section><section class="grid stats">{{range $k,$v:=.Stats}}<article><div class="stat-icon">◈</div><div><small>{{$k}}</small><strong>{{$v}}</strong></div></article>{{end}}</section>{{else if eq .Path "/users"}}{{if .ADUsers}}<section class="panel"><div class="panel-head"><div><h2>Active Directory users</h2><p>Import an account to make it available for badge assignment.</p></div><span class="count">{{len .ADUsers}} available</span></div><div class="table-wrap"><table><thead><tr><th>Username</th><th>Display name</th><th>Mail</th><th></th></tr></thead><tbody>{{range .ADUsers}}<tr><td><strong>{{.Username}}</strong></td><td>{{.DisplayName}}</td><td class="muted">{{.Mail}}</td><td class="actions"><form method="post" action="/directory/users/import"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><input type="hidden" name="username" value="{{.Username}}"><button class="small" type="submit">Import</button></form></td></tr>{{end}}</tbody></table></div></section>{{end}}<section class="panel"><div class="panel-head"><div><h2>Badge mappings</h2><p>Users currently managed by the identity gateway.</p></div><a class="button secondary" href="/pin">Manage PINs</a></div><div class="table-wrap"><table><thead><tr><th>ID</th><th>Username</th><th>Display name</th></tr></thead><tbody>{{range .Users}}<tr><td class="mono">#{{.ID}}</td><td><strong>{{.Username}}</strong></td><td>{{.DisplayName}}</td></tr>{{else}}<tr><td class="empty" colspan="3">No mappings yet.</td></tr>{{end}}</tbody></table></div></section>{{else if eq .Path "/badges"}}{{if .Payload}}<section class="panel secret"><div><span class="badge warning">One-time secret</span><h2>Badge created — save this now</h2><p>This QR secret cannot be recovered later.</p><code>{{.Payload}}</code></div><img alt="New badge QR code" src="/api/v1/badges/{{(index .Badges 0).ID}}/qr?payload={{urlquery .Payload}}"></section>{{end}}<section class="panel"><div class="panel-head"><div><h2>Issue a new badge</h2><p>Link a physical credential to an imported directory user.</p></div></div><form class="form-row" method="post" action="/badges"><input type="hidden" name="_csrf" value="{{.CSRF}}"><label><span>User</span><select name="user_id" required><option value="">Select user</option>{{range .Users}}<option value="{{.ID}}">{{.DisplayName}} ({{.Username}})</option>{{end}}</select></label><label><span>Description</span><input name="description" placeholder="e.g. Main badge"></label><button type="submit">Issue badge</button></form></section><section class="panel"><div class="panel-head"><div><h2>Issued badges</h2><p>Active and revoked physical credentials.</p></div></div><div class="table-wrap"><table><thead><tr><th>Badge</th><th>User</th><th>Status</th><th></th></tr></thead><tbody>{{range .Badges}}<tr><td class="mono">{{.BadgeCode}}</td><td><strong>{{.DisplayName}}</strong></td><td>{{if .Enabled}}<span class="badge success">Active</span>{{else}}<span class="badge neutral">Revoked</span>{{end}}</td><td class="actions">{{if .Enabled}}<form method="post" action="/badges/{{.ID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="danger small" type="submit">Revoke</button></form>{{end}}</td></tr>{{else}}<tr><td class="empty" colspan="4">No badges issued yet.</td></tr>{{end}}</tbody></table></div></section>{{else if eq .Path "/audit"}}<section class="panel"><div class="panel-head"><div><h2>Security events</h2><p>Authentication and administration activity recorded by SWBA.</p></div></div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Badge</th><th>User</th><th>Client</th><th>Result</th></tr></thead><tbody>{{range .Audits}}<tr><td class="muted">{{.Timestamp}}</td><td><strong>{{.EventType}}</strong></td><td class="mono">{{.BadgeID}}</td><td>{{.Username}}</td><td>{{.ClientID}}</td><td>{{if .Success}}<span class="badge success">Success</span>{{else}}<span class="badge danger-text">Denied</span>{{end}}</td></tr>{{else}}<tr><td class="empty" colspan="6">No audit events recorded.</td></tr>{{end}}</tbody></table></div></section>{{else}}<section class="grid status-grid"><article><span class="status-symbol">●</span><small>SERVER</small><strong>Online</strong><p>Authentication API is available.</p></article><article><span class="status-symbol">●</span><small>DATABASE</small><strong>SQLite ready</strong><p>Identity data store is available.</p></article><article><span class="status-symbol">●</span><small>DIRECTORY</small><strong>Connected</strong><p>Active Directory integration is ready.</p></article><article><span class="status-symbol">●</span><small>UPTIME</small><strong>{{.Uptime}}</strong><p>Current server process uptime.</p></article></section>{{end}}</main></body></html>`
const loginTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Sign in — StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body class="login-page"><main class="login-shell"><section class="login-brand"><a class="brand" href="/"><span class="brand-mark">S</span><span><strong>StumpfWorks</strong><small>Identity Platform</small></span></a><div><span class="kicker">Secure infrastructure access</span><h1>Identity you can hold in your hand.</h1><p>Badge-based authentication backed by Active Directory, Kerberos and short-lived credentials.</p></div><span class="login-foot">◉ &nbsp; LOGIN01 · EXAMPLE.TEST</span></section><section class="login-card"><div class="login-icon">◇</div><p class="eyebrow">ADMINISTRATION</p><h2>Welcome back</h2><p>Sign in with an authorized Active Directory account.</p><form class="login-form" method="post" action="/login"><label><span>AD username</span><input name="username" autocomplete="username" placeholder="alice-admin" required autofocus></label><label><span>Password</span><input type="password" name="password" autocomplete="current-password" placeholder="Enter your password" required></label><button type="submit">Sign in securely</button></form><p class="privacy">Credentials are verified over LDAPS and are never stored.</p></section></main></body></html>`
const pinTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>PIN management — StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="content standalone"><header class="topbar"><div><p class="eyebrow">STUMPFWORKS / IDENTITY</p><h1>PIN management</h1></div><a class="button secondary" href="/users">← Back to users</a></header><section class="panel"><div class="panel-head"><div><h2>User PINs</h2><p>PINs are stored exclusively as Argon2id hashes. An empty PIN disables authentication for that user.</p></div></div><div class="table-wrap"><table><thead><tr><th>User</th><th>Status</th><th>Action</th></tr></thead><tbody>{{range .Users}}<tr><td><strong>{{.DisplayName}}</strong><small class="user-handle">{{.Username}}</small></td><td>{{if .PINEnabled}}<span class="badge success">Enabled</span>{{else}}<span class="badge neutral">Disabled</span>{{end}}</td><td><form class="pin-form" method="post" action="/users/{{.ID}}/pin"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><input type="password" name="pin" inputmode="numeric" minlength="4" maxlength="32" placeholder="New PIN"><button type="submit">{{if .PINEnabled}}Change PIN{{else}}Enable PIN{{end}}</button>{{if .PINEnabled}}<button name="pin" value="" class="danger" formnovalidate>Disable</button>{{end}}</form></td></tr>{{end}}</tbody></table></div></section></main></body></html>`
const selfServiceTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Self-service — StumpfWorks Identity</title><link rel="stylesheet" href="/static/style.css"></head><body class="login-page"><main class="self-shell"><header class="self-header"><a class="brand" href="/self-service"><span class="brand-mark">S</span><span><strong>StumpfWorks</strong><small>Identity Self-Service</small></span></a><span class="status-chip"><i></i>Secure connection</span></header>{{if .Authenticated}}<section class="self-card"><div class="login-icon">◇</div><p class="eyebrow">YOUR BADGE ACCESS</p><h1>Hello, {{.User.DisplayName}}</h1><p class="self-intro">Choose a personal numeric PIN for badge authentication. Your Active Directory password remains unchanged.</p>{{if eq .Status "pin_updated"}}<div class="notice success-notice">PIN updated successfully. You can use it with your badge immediately.</div>{{else if eq .Status "badge_revoked"}}<div class="notice success-notice">The lost badge was disabled immediately.</div>{{end}}{{if .Error}}<div class="notice error-notice">{{if eq .Error "invalid_pin"}}PINs must match and contain 4 to 12 digits.{{else if eq .Error "session_expired"}}Your session expired. Please sign in again.{{else if eq .Error "badge_unavailable"}}That badge is unavailable or already disabled.{{else}}The request could not be completed. Please try again.{{end}}</div>{{end}}<div class="identity-row"><span class="avatar">◇</span><span><strong>{{.User.DisplayName}}</strong><small>{{.User.Username}}</small></span><span class="badge {{if .User.PINEnabled}}success{{else}}neutral{{end}}">PIN {{if .User.PINEnabled}}enabled{{else}}not set{{end}}</span></div><section class="self-badges"><div class="self-section-head"><div><h2>My active badges</h2><p>Only badges assigned to your account are shown.</p></div><span class="count">{{len .Badges}}</span></div>{{range .Badges}}<article class="self-badge-row"><span><strong>{{.BadgeCode}}</strong><small>{{if .Description}}{{.Description}}{{else}}Badge credential{{end}}</small></span><span><small>Issued {{.Created}}</small><small>Last used: {{.LastUsed}}</small></span><form method="post" action="/self-service/badges/{{.ID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="danger small" type="submit">Report lost</button></form></article>{{else}}<p class="self-empty">No active badges are assigned to your account.</p>{{end}}</section><form class="login-form" method="post" action="/self-service/pin"><input type="hidden" name="_csrf" value="{{.CSRF}}"><div class="pin-fields"><label><span>New PIN</span><input type="password" name="pin" inputmode="numeric" pattern="[0-9]{4,12}" minlength="4" maxlength="12" autocomplete="new-password" placeholder="4–12 digits" required></label><label><span>Confirm PIN</span><input type="password" name="pin_confirm" inputmode="numeric" pattern="[0-9]{4,12}" minlength="4" maxlength="12" autocomplete="new-password" placeholder="Repeat PIN" required></label></div><button type="submit">Save my PIN</button></form><div class="self-actions"><span>Your session expires automatically after 15 minutes.</span><form method="post" action="/self-service/logout"><input type="hidden" name="_csrf" value="{{.CSRF}}"><button class="link-button" type="submit">Sign out</button></form></div></section>{{else}}<section class="self-card"><div class="login-icon">◇</div><p class="eyebrow">BADGE SELF-SERVICE</p><h1>Manage your PIN</h1><p class="self-intro">Verify your identity with your Active Directory account, then set or change your personal badge PIN.</p>{{if .Error}}<div class="notice error-notice">{{if eq .Error "rate_limited"}}Too many attempts. Please wait ten minutes.{{else if eq .Error "unavailable"}}Self-service is temporarily unavailable.{{else}}Username or password was not accepted.{{end}}</div>{{end}}<form class="login-form" method="post" action="/self-service/login"><label><span>AD username</span><input name="username" autocomplete="username" placeholder="Your domain username" required autofocus></label><label><span>AD password</span><input type="password" name="password" autocomplete="current-password" placeholder="Your current password" required></label><button type="submit">Continue securely</button></form><p class="privacy">Your password is verified over LDAPS and is never stored.</p><a class="admin-link" href="/login">Administrator sign-in →</a></section>{{end}}</main></body></html>`
const selfServiceCSS = `.self-shell{position:relative;width:min(720px,100%);border:1px solid var(--line);border-radius:24px;overflow:hidden;background:rgba(10,21,35,.9);box-shadow:var(--shadow)}.self-header{display:flex;align-items:center;justify-content:space-between;padding:24px 28px;border-bottom:1px solid var(--line);background:rgba(6,15,26,.5)}.self-card{padding:42px;max-width:610px;margin:auto}.self-card h1{font-size:30px;margin:3px 0 8px}.self-intro{margin:0 0 25px;color:var(--muted)}.notice{padding:12px 14px;margin:18px 0;border-radius:10px;font-size:12px;font-weight:650}.success-notice{color:#b9f9df;background:rgba(67,221,161,.09);border:1px solid rgba(67,221,161,.2)}.error-notice{color:#ffc0cb;background:rgba(255,111,136,.09);border:1px solid rgba(255,111,136,.2)}.identity-row{display:flex;align-items:center;gap:12px;margin:22px 0;padding:15px;border-radius:12px;background:rgba(255,255,255,.025);border:1px solid var(--line)}.identity-row .avatar{width:38px;height:38px;display:grid;place-items:center;border-radius:50%;background:rgba(78,140,255,.13);color:#a8c3ff;font-weight:850}.identity-row strong,.identity-row small{display:block}.identity-row small{color:var(--muted);font-size:11px}.identity-row .badge{margin-left:auto}.self-badges{margin:22px 0;padding:18px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.018)}.self-section-head{display:flex;justify-content:space-between;align-items:start;margin-bottom:12px}.self-section-head h2{font-size:15px;margin:0}.self-section-head p{font-size:11px;color:var(--muted);margin:2px 0 0}.self-badge-row{display:grid;grid-template-columns:1fr auto auto;align-items:center;gap:18px;padding:12px 0;border-top:1px solid var(--line)}.self-badge-row strong,.self-badge-row small{display:block}.self-badge-row small,.self-empty{color:var(--muted);font-size:10px}.self-empty{margin:0}.pin-fields{display:grid;grid-template-columns:1fr 1fr;gap:12px}.self-actions{display:flex;align-items:center;justify-content:space-between;margin-top:22px;padding-top:18px;border-top:1px solid var(--line);color:#63778e;font-size:10px}.link-button{padding:0;background:none;border:0;color:#9ab4d1;font-size:11px}.admin-link{display:block;margin-top:22px;text-align:center;color:#7890aa;font-size:11px;text-decoration:none}@media(max-width:680px){.self-header{padding:20px}.self-header .status-chip{display:none}.self-card{padding:28px 22px}.pin-fields{grid-template-columns:1fr}.identity-row{align-items:flex-start;flex-wrap:wrap}.identity-row .badge{margin-left:50px}.self-badge-row{grid-template-columns:1fr}.self-badge-row .badge{justify-self:start}}`
const css = `:root{color-scheme:dark;font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;--bg:#07101d;--bg2:#0b1727;--panel:rgba(17,31,49,.88);--panel-solid:#111f31;--panel-raised:#16263a;--line:rgba(142,174,208,.16);--line-strong:rgba(142,174,208,.28);--text:#eff6ff;--muted:#8fa4bc;--accent:#43dda1;--accent2:#4e8cff;--danger:#ff6f88;--shadow:0 24px 70px rgba(0,0,0,.28)}*{box-sizing:border-box}html{min-height:100%;background:var(--bg)}body{margin:0;min-height:100vh;background:radial-gradient(circle at 75% 0,rgba(36,91,145,.2),transparent 32%),linear-gradient(145deg,var(--bg2),var(--bg) 62%);color:var(--text);display:flex}body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.16;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:44px 44px}a{color:inherit}.sidebar{position:sticky;top:0;width:260px;height:100vh;padding:30px 22px 22px;border-right:1px solid var(--line);background:rgba(6,14,25,.72);backdrop-filter:blur(18px);display:flex;flex-direction:column;z-index:2}.brand{display:flex;align-items:center;gap:12px;text-decoration:none}.brand-mark{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:linear-gradient(145deg,var(--accent),#20a879);color:#04110d;font-size:21px;font-weight:900;box-shadow:0 8px 28px rgba(67,221,161,.2)}.brand strong,.brand small{display:block}.brand strong{font-size:16px;letter-spacing:.2px}.brand small{font-size:11px;color:var(--muted);letter-spacing:.9px;text-transform:uppercase}.sidebar nav{display:grid;gap:6px;margin-top:42px}.sidebar nav a{display:flex;align-items:center;gap:13px;color:var(--muted);text-decoration:none;padding:11px 13px;border:1px solid transparent;border-radius:10px;font-weight:600;transition:.18s ease}.sidebar nav a span{width:20px;text-align:center;color:#66809d;font-size:17px}.sidebar nav a:hover{background:rgba(255,255,255,.035);color:var(--text)}.sidebar nav a.active{background:linear-gradient(90deg,rgba(67,221,161,.13),rgba(67,221,161,.04));border-color:rgba(67,221,161,.2);color:#dffff3}.sidebar nav a.active span{color:var(--accent)}.sidebar-foot{margin-top:auto;display:grid;gap:13px}.server-state{display:flex;align-items:center;gap:10px;padding:12px;border:1px solid var(--line);border-radius:11px;background:rgba(255,255,255,.025)}.server-state i,.status-chip i{width:8px;height:8px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px rgba(67,221,161,.8)}.server-state strong,.server-state small{display:block}.server-state strong{font-size:12px}.server-state small{font-size:11px;color:var(--muted)}.sidebar-foot form{display:block}.ghost{width:100%;background:transparent;border:1px solid var(--line);color:var(--muted)}.version{color:#61758c;font-size:10px;text-align:center}.content{position:relative;width:100%;max-width:1440px;padding:42px 48px 70px;margin:0 auto}.topbar{display:flex;align-items:center;justify-content:space-between;gap:24px;margin-bottom:30px}.eyebrow{margin:0 0 4px;color:var(--accent);font-size:10px;font-weight:800;letter-spacing:2.3px}.topbar h1{font-size:32px;line-height:1.2;margin:0;letter-spacing:-.7px}.status-chip,.badge,.count,.kicker{display:inline-flex;align-items:center;gap:8px;border-radius:999px;font-weight:700}.status-chip{padding:8px 12px;border:1px solid rgba(67,221,161,.2);background:rgba(67,221,161,.07);color:#a9f6d8;font-size:11px}.panel{margin-top:18px;padding:25px;background:linear-gradient(145deg,rgba(20,37,57,.9),rgba(13,26,42,.9));border:1px solid var(--line);border-radius:17px;box-shadow:0 14px 45px rgba(0,0,0,.12);overflow:hidden}.panel h2{font-size:18px;margin:0 0 3px}.panel p{margin:0;color:var(--muted)}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:20px}.hero{min-height:190px;display:flex;align-items:center;justify-content:space-between;padding:35px 40px;overflow:hidden;position:relative;background:radial-gradient(circle at 85% 50%,rgba(67,221,161,.17),transparent 25%),linear-gradient(130deg,#142943,#0e1b2c)}.hero h2{font-size:28px;margin:12px 0 8px}.hero p{max-width:620px;font-size:16px}.kicker{padding:5px 10px;background:rgba(78,140,255,.12);border:1px solid rgba(78,140,255,.25);color:#9dbdff;font-size:10px;text-transform:uppercase;letter-spacing:1px}.hero-icon{width:105px;height:105px;border-radius:50%;display:grid;place-items:center;color:var(--accent);border:1px solid rgba(67,221,161,.25);background:rgba(67,221,161,.06);font-size:52px;box-shadow:0 0 60px rgba(67,221,161,.12)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px}.stats{margin-top:18px}.stats article,.status-grid article{background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:21px}.stats article{display:flex;align-items:center;gap:15px}.stat-icon{width:39px;height:39px;display:grid;place-items:center;border-radius:10px;color:#93b8ff;background:rgba(78,140,255,.1)}.grid small{display:block;color:var(--muted);font-size:10px;font-weight:800;letter-spacing:1.2px;text-transform:uppercase}.grid strong{display:block;font-size:25px;line-height:1.2;margin-top:4px}.status-grid article{position:relative;min-height:155px}.status-grid .status-symbol{position:absolute;right:18px;top:16px;color:var(--accent);font-size:12px}.status-grid strong{font-size:20px;margin-top:14px}.status-grid p{font-size:12px;margin-top:9px}.count{padding:5px 10px;background:rgba(255,255,255,.04);border:1px solid var(--line);color:var(--muted);font-size:10px}.table-wrap{overflow:auto;margin:0 -25px -25px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:14px 25px;border-top:1px solid var(--line);white-space:nowrap}th{color:#71879f;background:rgba(3,10,18,.22);font-size:10px;letter-spacing:1px;text-transform:uppercase}td{color:#c8d5e4}td strong{color:var(--text)}tr:hover td{background:rgba(255,255,255,.017)}.muted{color:var(--muted)}.mono{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:#a9bdd3}.actions{text-align:right}.actions form{justify-content:flex-end}.empty{text-align:center!important;color:var(--muted);padding:35px}.badge{padding:4px 9px;font-size:10px}.badge.success{color:#a9f6d8;background:rgba(67,221,161,.1);border:1px solid rgba(67,221,161,.2)}.badge.neutral{color:#aebdd0;background:rgba(174,189,208,.08);border:1px solid var(--line)}.badge.warning{color:#ffd58a;background:rgba(255,184,66,.09);border:1px solid rgba(255,184,66,.2)}.badge.danger-text{color:#ffadbb;background:rgba(255,111,136,.09);border:1px solid rgba(255,111,136,.2)}form{display:flex;gap:10px;flex-wrap:wrap}label{display:grid;gap:6px;color:#aebed0;font-size:11px;font-weight:700}input,select,button,.button{font:inherit;padding:11px 14px;border:1px solid var(--line-strong);border-radius:9px;background:#0a1523;color:var(--text);outline:none;transition:.16s ease}input:focus,select:focus{border-color:var(--accent2);box-shadow:0 0 0 3px rgba(78,140,255,.12)}button,.button{display:inline-flex;justify-content:center;align-items:center;background:linear-gradient(135deg,#377ce5,#4e8cff);border-color:transparent;font-weight:750;cursor:pointer;text-decoration:none}button:hover,.button:hover{filter:brightness(1.1);transform:translateY(-1px)}button.small{padding:7px 11px;font-size:12px}.secondary{background:rgba(255,255,255,.04);border-color:var(--line-strong);color:#cad8e8}.danger{background:rgba(255,111,136,.12);border-color:rgba(255,111,136,.24);color:#ffadbb}.form-row{align-items:end}.form-row label{min-width:220px;flex:1}.secret{display:flex;align-items:center;justify-content:space-between;gap:35px;border-color:rgba(255,184,66,.26)}.secret h2{margin-top:12px}.secret img{width:190px;padding:10px;border-radius:13px;background:white}.secret code{display:block;max-width:720px;margin-top:16px;padding:12px;border-radius:8px;background:#08111c;color:#ffd58a;word-break:break-all}.standalone{max-width:1200px}.pin-form{flex-wrap:nowrap}.user-handle{display:block;color:var(--muted)}.login-page{display:grid;place-items:center;padding:32px}.login-shell{position:relative;width:min(960px,100%);min-height:600px;display:grid;grid-template-columns:1.15fr .85fr;border:1px solid var(--line);border-radius:24px;overflow:hidden;background:rgba(10,21,35,.88);box-shadow:var(--shadow)}.login-brand{padding:44px;display:flex;flex-direction:column;justify-content:space-between;background:radial-gradient(circle at 20% 80%,rgba(67,221,161,.16),transparent 32%),linear-gradient(145deg,rgba(25,54,84,.85),rgba(8,22,37,.9))}.login-brand h1{max-width:470px;margin:15px 0 13px;font-size:45px;line-height:1.08;letter-spacing:-1.6px}.login-brand p{max-width:470px;color:#a8bbce;font-size:16px}.login-foot{font-size:10px;color:#71879e;letter-spacing:1px}.login-card{padding:48px 42px;display:flex;flex-direction:column;justify-content:center;background:rgba(8,17,29,.72)}.login-icon{width:54px;height:54px;margin-bottom:24px;border-radius:15px;display:grid;place-items:center;background:rgba(67,221,161,.1);border:1px solid rgba(67,221,161,.2);color:var(--accent);font-size:28px}.login-card h2{font-size:28px;margin:2px 0 7px}.login-card>p:not(.eyebrow):not(.privacy){color:var(--muted);margin:0}.login-form{display:grid;margin-top:30px}.login-form input,.login-form button{width:100%;padding:13px}.login-form button{margin-top:8px}.privacy{margin-top:20px!important;text-align:center;color:#63778e!important;font-size:10px}.login-page:before{opacity:.24}@media(max-width:850px){.content{padding:32px 25px}.sidebar{width:220px}.secret{align-items:flex-start}.login-shell{grid-template-columns:1fr;max-width:520px}.login-brand{min-height:270px;padding:32px}.login-brand h1{font-size:34px}.login-foot{display:none}.login-card{padding:38px 32px}}@media(max-width:680px){body{display:block}.sidebar{position:relative;width:100%;height:auto;padding:20px;border-right:0;border-bottom:1px solid var(--line)}.sidebar nav{grid-template-columns:repeat(5,1fr);margin-top:20px;gap:4px}.sidebar nav a{justify-content:center;padding:10px 5px;font-size:0}.sidebar nav a span{font-size:18px}.sidebar-foot{display:none}.content{padding:25px 16px 50px}.topbar{align-items:flex-start}.status-chip{font-size:0;padding:10px}.panel{padding:19px}.table-wrap{margin:0 -19px -19px}th,td{padding:13px 19px}.hero{padding:27px;min-height:170px}.hero-icon{display:none}.hero h2{font-size:23px}.panel-head{align-items:flex-start;flex-direction:column}.secret{display:block}.secret img{margin-top:22px}.form-row{display:grid}.pin-form{flex-wrap:wrap}.login-page{padding:15px}.login-brand{min-height:230px;padding:25px}.login-brand h1{font-size:29px}.login-card{padding:30px 25px}}`
