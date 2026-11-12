package app

import (
	"net/http"

	"github.com/razzie-cloud/access-gateway/internal/web"
)

var staticFiles = http.FileServer(http.FS(web.Assets))

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.methodNotAllowed(w, r, "GET, HEAD")
		return
	}
	response := &assetResponse{ResponseWriter: w}
	staticFiles.ServeHTTP(response, r)
	if response.status >= 400 {
		// FileServer authors plain-text errors (including invalid ranges). Replace
		// only those bodies; successful assets and redirects pass through directly.
		w.Header().Del("Content-Length")
		s.writeError(w, r, response.status, http.StatusText(response.status))
	}
}

type assetResponse struct {
	http.ResponseWriter
	status int
}

func (w *assetResponse) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	if status < 400 {
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *assetResponse) Write(data []byte) (int, error) {
	if w.status >= 400 {
		return len(data), nil
	}
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}
