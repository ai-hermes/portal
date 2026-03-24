package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// NewAppHandler serves API endpoints and, when available, frontend static files.
// Non-API routes fallback to index.html for SPA history routing.
func NewAppHandler(apiHandler http.Handler, webDir string) http.Handler {
	if strings.TrimSpace(webDir) == "" {
		return apiHandler
	}

	indexPath := filepath.Join(webDir, "index.html")
	if info, err := os.Stat(indexPath); err != nil || info.IsDir() {
		return apiHandler
	}

	staticFiles := http.FileServer(http.Dir(webDir))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if isAPIRequest(req.URL.Path) {
			apiHandler.ServeHTTP(w, req)
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.NotFound(w, req)
			return
		}

		requestPath := filepath.Clean("/" + req.URL.Path)
		if requestPath != "/" {
			candidate := filepath.Join(webDir, strings.TrimPrefix(requestPath, "/"))
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				staticFiles.ServeHTTP(w, req)
				return
			}
		}

		http.ServeFile(w, req, indexPath)
	})
}

func isAPIRequest(path string) bool {
	return path == "/healthz" || path == "/api" || strings.HasPrefix(path, "/api/")
}

