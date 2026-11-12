package app

import (
	"bytes"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/razzie-cloud/access-gateway/internal/logging"
)

// Prefer HTML on ties, except an explicit JSON preference or an unqualified
// JSON-body request. A request's Content-Type never overrides an explicit Accept.
func wantsJSON(r *http.Request) bool {
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	accept := strings.Join(r.Header.Values("Accept"), ",")
	if strings.TrimSpace(accept) == "" {
		return contentType == "application/json"
	}
	type preference struct {
		quality     float64
		specificity int
	}
	json, html := preference{specificity: -1}, preference{specificity: -1}
	for _, entry := range strings.Split(accept, ",") {
		media, params, err := mime.ParseMediaType(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		quality := 1.0
		if raw, ok := params["q"]; ok {
			quality, err = strconv.ParseFloat(raw, 64)
			if err != nil || !(quality >= 0 && quality <= 1) {
				continue
			}
		}
		for offered, pref := range map[string]*preference{"application/json": &json, "text/html": &html} {
			specificity := -1
			switch {
			case media == offered:
				specificity = 2
			case media == strings.SplitN(offered, "/", 2)[0]+"/*":
				specificity = 1
			case media == "*/*":
				specificity = 0
			}
			if specificity >= 0 && (specificity > pref.specificity || (specificity == pref.specificity && quality > pref.quality)) {
				*pref = preference{quality, specificity}
			}
		}
	}
	if json.quality != html.quality {
		return json.quality > html.quality
	}
	if json.quality == 0 {
		return false
	}
	if json.specificity != html.specificity {
		return json.specificity > html.specificity
	}
	return json.specificity == 0 && contentType == "application/json"
}

type errorPage struct {
	Status                      int
	Label, Title, Message, Hint string
}

func errorPageFor(status int, message string) *errorPage {
	page := &errorPage{
		Status: status, Label: http.StatusText(status), Title: http.StatusText(status),
		Message: message, Hint: "Return to cloud home or open your account to continue.",
	}
	switch status {
	case http.StatusBadRequest, http.StatusUnsupportedMediaType, http.StatusRequestEntityTooLarge:
		page.Title = "Unable to complete this request"
		page.Hint = "Check your request and try again."
	case http.StatusUnauthorized:
		page.Title = "Sign in required"
		page.Hint = "Open your account to sign in, then return to the app."
	case http.StatusForbidden:
		page.Label, page.Title = "Access denied", "Access denied"
		page.Hint = "Need access? Contact your Razzie Cloud administrator."
		if message == "Administrator access required" {
			page.Title = message
			page.Message = "You’re signed in, but your account doesn’t have permission to open this page."
		}
	case http.StatusNotFound:
		page.Title = "Page not found"
		if message == "Page not found" {
			page.Message = "The page you’re looking for doesn’t exist or is no longer available."
		}
	case http.StatusMethodNotAllowed:
		page.Title = "Method not allowed"
		page.Message = "This page doesn’t support that request method."
	case http.StatusConflict:
		page.Title = "Unable to save changes"
		page.Hint = "Review the message above before trying again."
	case http.StatusTooManyRequests:
		page.Title = "Too many requests"
		page.Message = "You’ve made too many requests in a short time."
		page.Hint = "Please wait a moment before trying again."
	case http.StatusInternalServerError:
		page.Title = "Something went wrong"
		page.Hint = "Please try again. If the problem continues, contact your administrator."
		if message == "db error" || message == "webauthn error" {
			page.Message = "We couldn’t complete your request."
		}
	case http.StatusServiceUnavailable:
		page.Title = "Temporarily unavailable"
		page.Hint = "Please try again in a few moments."
	}
	// Translate protocol-oriented API messages for people while preserving the
	// original JSON error strings for existing clients.
	switch message {
	case "bad json":
		page.Message = "The request couldn’t be read. Please return to the app and try again."
	case "missing sid":
		page.Message = "Your registration session is missing. Please start registration again."
	case "application/json required":
		page.Message = "The request uses an unsupported format."
	case "request origin not allowed":
		page.Message = "This request came from an unrecognized page."
	case "Forward authentication is not configured":
		page.Message = "Access to this app hasn’t been configured yet."
	case "Invalid user ID", "User name cannot be sent as an HTTP header":
		page.Message = "We couldn’t verify your account."
	}
	return page
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request, allow string) {
	w.Header().Set("Allow", allow)
	s.writeError(w, r, http.StatusMethodNotAllowed, "Method not allowed")
}

// All messages passed here must be safe, classified user-facing messages. Never
// include backend errors, request URLs, credentials, usernames or callback state.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Add("Vary", "Accept, Content-Type, HX-Request")
	if wantsJSON(r) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
		} else {
			writeJSON(w, status, map[string]string{"error": message})
		}
		return
	}
	name := "error-page"
	data := viewData{
		GatewayOrigin: strings.TrimRight(s.cfg.Origin, "/"),
		LandingOrigin: strings.TrimRight(s.cfg.LandingOrigin, "/"),
		Failure:       errorPageFor(status, message), Error: message,
	}
	if data.LandingOrigin == "" {
		data.LandingOrigin = "https://razzie.cloud"
	}
	if r.Header.Get("HX-Request") == "true" && strings.HasPrefix(r.URL.Path, "/ui/") {
		// Keep the live shell, drafts and form target when HTMX requests a fragment.
		name = "message"
	} else {
		// The proxy may display this page on any protected app's origin. Only the
		// configured gateway may supply assets; the error page needs no scripts.
		origin := data.GatewayOrigin
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src "+origin+"; img-src "+origin+"; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	}
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		logging.Fields(r.Context(), "template", name)
		logging.Fail(r.Context(), slog.LevelError, "render_template", err)
		// Last resort if the error template itself fails; do not recurse.
		http.Error(w, "Unable to render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}
