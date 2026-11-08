package server

import (
	"context"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreateipc"
	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
	"net/http"
	"time"
)

// ConfigureADUserCreation attaches an explicit backend before serving requests.
// It neither enables the backend nor creates a writer/transport. Nil disables it.
// The shipped command attaches only an explicitly enabled local transport.
func (s *Server) ConfigureADUserCreation(backend adcreate.Operations) error {
	if backend != nil {
		d, ok := s.dir.(directory.UserCreationSessionDirectory)
		if !s.protect || s.sessions == nil || !ok || !d.UserCreationSessionsAllowed() {
			return adcreate.ErrDenied
		}
	}
	s.creationOps = backend
	return nil
}

// ConfigureADUserCreationTransport attaches only a local client; it never opens
// a directory connection or creates an executor. Call before serving requests.
func (s *Server) ConfigureADUserCreationTransport(c adcreateipc.Config) error {
	client, e := adcreateipc.NewClient(c)
	if e != nil {
		return e
	}
	if !client.IsEnabled() {
		return s.ConfigureADUserCreation(nil)
	}
	return s.ConfigureADUserCreation(client)
}
func (s *Server) adUserCreationSession(r *http.Request) (string, string, error) {
	if !s.protect || s.sessions == nil || r.TLS == nil {
		return "", "", adcreate.ErrDenied
	}
	d, ok := s.dir.(directory.UserCreationSessionDirectory)
	if !ok || !d.UserCreationSessionsAllowed() {
		return "", "", adcreate.ErrDenied
	}
	token := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == "swbadge_emergency_admin" {
			return "", "", adcreate.ErrDenied
		}
		if c.Name == "swbadge_admin" {
			token = c.Value
			count++
		}
	}
	if count != 1 {
		return "", "", adcreate.ErrDenied
	}
	username, e := s.sessions.Verify(token, time.Now())
	if e != nil {
		return "", "", adcreate.ErrDenied
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	roles, e := d.AdministrativeRoles(ctx, username)
	if e != nil || !adminauth.Allowed(adminauth.PermissionDirectoryUsersCreate, roles...) {
		return "", "", adcreate.ErrDenied
	}
	return username, s.sessions.CSRF(token), nil
}
func (s *Server) adUserCreation(w http.ResponseWriter, r *http.Request) {
	if s.creationOps == nil {
		w.Header().Set("Cache-Control", "no-store")
		s.problem(w, 403, "ad_user_creation_disabled")
		return
	}
	adcreate.Handler{Service: s.creationOps, Session: s.adUserCreationSession}.ServeHTTP(w, r)
}
