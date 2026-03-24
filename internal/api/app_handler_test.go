package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/warjiang/portal/internal/api"
)

func TestAppHandlerFallbackToIndex(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.html"), "<html>spa</html>")
	writeFile(t, filepath.Join(dir, "assets", "main.js"), "console.log('ok')")

	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("api"))
	})
	h := api.NewAppHandler(apiHandler, dir)

	apiReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	apiRes := httptest.NewRecorder()
	h.ServeHTTP(apiRes, apiReq)
	if apiRes.Code != http.StatusTeapot {
		t.Fatalf("expected api response, got %d", apiRes.Code)
	}

	assetReq := httptest.NewRequest(http.MethodGet, "/assets/main.js", nil)
	assetRes := httptest.NewRecorder()
	h.ServeHTTP(assetRes, assetReq)
	if assetRes.Code != http.StatusOK {
		t.Fatalf("expected asset 200, got %d", assetRes.Code)
	}

	spaReq := httptest.NewRequest(http.MethodGet, "/members", nil)
	spaRes := httptest.NewRecorder()
	h.ServeHTTP(spaRes, spaReq)
	if spaRes.Code != http.StatusOK {
		t.Fatalf("expected fallback 200, got %d", spaRes.Code)
	}
	if got := spaRes.Body.String(); got != "<html>spa</html>" {
		t.Fatalf("unexpected fallback content: %q", got)
	}
}

func TestAppHandlerWithoutIndexFallsBackToAPIOnly(t *testing.T) {
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := api.NewAppHandler(apiHandler, t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("expected api-only fallback, got %d", res.Code)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
}

