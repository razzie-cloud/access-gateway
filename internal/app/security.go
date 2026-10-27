package app

import (
	"mime"
	"net/http"
	"strings"
)

func (s *Server) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.Method == http.MethodPost {
			if r.Header.Get("Origin") != strings.TrimRight(s.cfg.Origin, "/") {
				writeJSON(w, 403, map[string]string{"error": "request origin not allowed"})
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api/") {
				mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || mediaType != "application/json" {
					writeJSON(w, 415, map[string]string{"error": "application/json required"})
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		}
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	sameSite := http.SameSiteStrictMode
	if name == "auth" {
		// The gateway session must accompany top-level navigation from other sites.
		// Mutations still require an exact Origin match in handler().
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.cfg.Origin, "https://"), SameSite: sameSite, MaxAge: maxAge})
}

func (s *Server) currentUser(r *http.Request) (User, error) {
	cookie, err := r.Cookie("auth")
	if err != nil {
		return User{}, err
	}
	username, ok, err := s.sessions.GetAuth(r.Context(), cookie.Value)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, http.ErrNoCookie
	}
	return s.getUserByUsername(r.Context(), username)
}
