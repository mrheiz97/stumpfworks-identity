package server

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
)

type compactAdminNavItem struct {
	path, icon, label string
	permission        adminauth.Permission
}

var compactAdminNavigation = []compactAdminNavItem{
	{path: "/users", icon: "◎", label: "Users", permission: adminauth.PermissionIdentityRead},
	{path: "/badges", icon: "◇", label: "Badges", permission: adminauth.PermissionCredentialsRead},
	{path: "/audit", icon: "≡", label: "Audit log", permission: adminauth.PermissionAuditRead},
	{path: "/oidc-clients", icon: "↗", label: "OIDC clients", permission: adminauth.PermissionOIDCRead},
	{path: "/oidc-sessions", icon: "◌", label: "OIDC sessions", permission: adminauth.PermissionOIDCSessionsRead},
	{path: "/status", icon: "◉", label: "System status", permission: adminauth.PermissionSystemRead},
}

func (s *Server) renderCompactAdminPage(w http.ResponseWriter, r *http.Request, pageTemplate *template.Template, data any, activePath string) error {
	var rendered bytes.Buffer
	if err := pageTemplate.Execute(&rendered, data); err != nil {
		return err
	}
	body := rendered.String()
	marker := "<body><main"
	if !strings.Contains(body, marker) {
		return fmt.Errorf("compact administration page has no body/main boundary")
	}
	body = strings.Replace(body, marker, "<body>"+s.compactAdminSidebar(r, activePath)+"<main", 1)
	_, err := fmt.Fprint(w, body)
	return err
}

func (s *Server) compactAdminSidebar(r *http.Request, activePath string) string {
	var navigation strings.Builder
	navigation.WriteString(compactAdminLink("/", "◈", "Dashboard", activePath == "/"))
	for _, item := range compactAdminNavigation {
		if s.unprotectedOrCan(r, item.permission) {
			navigation.WriteString(compactAdminLink(item.path, item.icon, item.label, activePath == item.path))
		}
	}
	csrf := ""
	if s.sessions != nil {
		csrf = s.sessions.CSRF(administrativeCookieToken(r))
	}
	return `<aside class="sidebar"><a class="brand" href="/"><span class="brand-mark">S</span><span><strong>StumpfWorks</strong><small>Identity Platform</small></span></a><nav aria-label="Main navigation">` + navigation.String() + `</nav><div class="sidebar-foot"><div class="server-state"><i></i><span><strong>LOGIN01</strong><small>Operational</small></span></div><form method="post" action="/logout"><input type="hidden" name="_csrf" value="` + template.HTMLEscapeString(csrf) + `"><button class="ghost" type="submit">Sign out</button></form><small class="version">Identity v` + template.HTMLEscapeString(version.Version) + `</small></div></aside>`
}

func compactAdminLink(path, icon, label string, active bool) string {
	class := ""
	if active {
		class = ` class="active"`
	}
	return `<a` + class + ` href="` + template.HTMLEscapeString(path) + `"><span>` + template.HTMLEscapeString(icon) + `</span>` + template.HTMLEscapeString(label) + `</a>`
}
