package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

const appCallbackPath = "/_auth/callback"

// publicOrigin accepts HTTPS origins and loopback HTTP origins for development.
// Exact origins, rather than suffixes, keep apps from choosing arbitrary callbacks.
func publicOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.ContainsAny(u.Host, "\\*,") {
		return "", fmt.Errorf("invalid public origin %q", raw)
	}
	if u.Scheme != "https" {
		host := strings.ToLower(u.Hostname())
		ip := net.ParseIP(host)
		// Browsers resolve the reserved .localhost namespace to loopback. This
		// permits separate app cookie hosts through WSL's localhost forwarding.
		local := host == "localhost" || strings.HasSuffix(host, ".localhost") || (ip != nil && ip.IsLoopback())
		if u.Scheme != "http" || !local {
			return "", fmt.Errorf("public origin must use HTTPS (HTTP is allowed on loopback): %q", raw)
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

func validateForwardAuthConfig(cfg Config) error {
	if len(cfg.ForwardAuthOrigins) == 0 {
		return nil
	}
	origin, err := publicOrigin(cfg.Origin)
	if err != nil {
		return fmt.Errorf("forward auth gateway: %w", err)
	}
	for _, raw := range cfg.ForwardAuthOrigins {
		appOrigin, err := publicOrigin(raw)
		if err != nil {
			return fmt.Errorf("forward auth app: %w", err)
		}
		if appOrigin == origin {
			return errors.New("forward auth app origin must differ from the gateway origin")
		}
	}
	return nil
}

func (s *Server) allowedAppOrigin(origin string) bool {
	for _, raw := range s.cfg.ForwardAuthOrigins {
		allowed, err := publicOrigin(raw)
		if err == nil && origin == allowed {
			return true
		}
	}
	return false
}

// Only the reverse proxy may supply these headers. Caddy overwrites them with
// the original request's values. Never infer an app origin from the backend Host.
func (s *Server) forwardedAppURL(r *http.Request) (*url.URL, error) {
	for _, name := range []string{"X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Uri"} {
		if len(r.Header.Values(name)) != 1 {
			return nil, errors.New("one forwarded proto, host and URI required")
		}
	}
	rawOrigin := r.Header.Get("X-Forwarded-Proto") + "://" + r.Header.Get("X-Forwarded-Host")
	origin, err := publicOrigin(rawOrigin)
	if err != nil || !s.allowedAppOrigin(origin) {
		return nil, errors.New("app origin not allowed")
	}
	rawURI := r.Header.Get("X-Forwarded-Uri")
	u, err := url.ParseRequestURI(rawURI)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(rawURI, "/") ||
		strings.HasPrefix(rawURI, "//") || strings.ContainsAny(u.Path, "\\\r\n\x00") {
		return nil, errors.New("invalid forwarded URI")
	}
	base, _ := url.Parse(origin)
	u.Scheme, u.Host = base.Scheme, base.Host
	return u, nil
}

func appCookieName(origin, name string) string {
	if strings.HasPrefix(origin, "https://") {
		return "__Host-razcloud_" + name
	}
	return "razcloud_" + name
}

func setAppCookie(w http.ResponseWriter, origin, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: appCookieName(origin, name), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: strings.HasPrefix(origin, "https://"), SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if len(s.cfg.ForwardAuthOrigins) == 0 {
		http.Error(w, "Forward authentication is not configured", http.StatusServiceUnavailable)
		return
	}
	target, err := s.forwardedAppURL(r)
	if err != nil {
		http.Error(w, "Invalid forwarded app request", http.StatusBadRequest)
		return
	}
	origin := target.Scheme + "://" + target.Host
	if target.Path == appCallbackPath {
		s.handleAppCallback(w, r, origin, target)
		return
	}
	if cookie, err := r.Cookie(appCookieName(origin, "app")); err == nil {
		username, ok, err := s.sessions.getAppAuth(r.Context(), cookie.Value, origin)
		if err != nil {
			http.Error(w, "Session storage unavailable", http.StatusServiceUnavailable)
			return
		}
		if ok {
			user, err := s.getUserByUsername(r.Context(), username)
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "User no longer exists", http.StatusUnauthorized)
				return
			}
			if err != nil {
				http.Error(w, "Unable to validate user", http.StatusServiceUnavailable)
				return
			}
			if strings.ContainsFunc(user.Username, func(r rune) bool { return r < 32 || r == 127 }) {
				http.Error(w, "User name cannot be sent as an HTTP header", http.StatusInternalServerError)
				return
			}
			id, err := uuid.FromBytes(user.ID)
			if err != nil {
				http.Error(w, "Invalid user ID", http.StatusInternalServerError)
				return
			}
			w.Header().Set("X-Auth-Request-User", id.String())
			w.Header().Set("X-Auth-Request-Name", user.Username)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	flow, state, err := s.sessions.beginAppLogin(r.Context(), origin, target.String())
	if err != nil {
		http.Error(w, "Unable to start sign-in; try again later", http.StatusServiceUnavailable)
		return
	}
	setAppCookie(w, origin, "state_"+flow, state, int(appLoginTTL.Seconds()))
	http.Redirect(w, r, strings.TrimRight(s.cfg.Origin, "/")+"/auth/authorize?flow="+url.QueryEscape(flow), http.StatusSeeOther)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	flowID := r.URL.Query().Get("flow")
	flow, ok, err := s.sessions.appLogin(r.Context(), flowID)
	if err != nil {
		http.Error(w, "Session storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if !ok || !s.allowedAppOrigin(flow.origin) {
		http.Error(w, "Sign-in expired; return to the app and try again", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie("auth")
	if err == nil {
		code, ok, err := s.sessions.authorizeAppLogin(r.Context(), flowID, cookie.Value)
		if err != nil {
			http.Error(w, "Session storage unavailable", http.StatusServiceUnavailable)
			return
		}
		if ok {
			callback := flow.origin + appCallbackPath + "?" + url.Values{"state": {flowID}, "code": {code}}.Encode()
			http.Redirect(w, r, callback, http.StatusSeeOther)
			return
		}
	}
	// Keep the flow in the address bar across the existing passkey UI. After a
	// successful login app.js reloads this URL to complete the handoff.
	data, err := s.state(r)
	if err != nil {
		http.Error(w, "Unable to load sign-in", http.StatusServiceUnavailable)
		return
	}
	render(w, http.StatusOK, "page", data)
}

func (s *Server) handleAppCallback(w http.ResponseWriter, r *http.Request, origin string, target *url.URL) {
	if r.Header.Get("X-Forwarded-Method") != http.MethodGet {
		http.Error(w, "Callback requires GET", http.StatusMethodNotAllowed)
		return
	}
	query, err := url.ParseQuery(target.RawQuery)
	if err != nil || len(query["state"]) != 1 || len(query["code"]) != 1 {
		http.Error(w, "Invalid sign-in callback", http.StatusBadRequest)
		return
	}
	flowID := query.Get("state")
	cookie, err := r.Cookie(appCookieName(origin, "state_"+flowID))
	if err != nil {
		http.Error(w, "Missing sign-in state; return to the app and try again", http.StatusBadRequest)
		return
	}
	token, returnTo, ok, err := s.sessions.completeAppLogin(r.Context(), flowID, query.Get("code"), cookie.Value, origin)
	if err != nil {
		http.Error(w, "Session storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if !ok {
		http.Error(w, "Invalid or expired sign-in; return to the app and try again", http.StatusBadRequest)
		return
	}
	setAppCookie(w, origin, "app", token, 0)
	setAppCookie(w, origin, "state_"+flowID, "", -1)
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}
