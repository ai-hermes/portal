package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/warjiang/portal/internal/api"
)

func TestHealthz(t *testing.T) {
	h := api.NewRouter(api.Dependencies{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

func TestLiteLLMAdminRequiresAuth(t *testing.T) {
	h := api.NewRouter(api.Dependencies{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/litellm/events", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d", w.Code)
	}
}
