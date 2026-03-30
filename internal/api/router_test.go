package api_test

import (
	"encoding/json"
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

func TestLiteLLMModelsRequiresAuth(t *testing.T) {
	h := api.NewRouter(api.Dependencies{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/litellm/me/models", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d", w.Code)
	}
}

func TestLiteLLMConfigIsPublic(t *testing.T) {
	h := api.NewRouter(api.Dependencies{
		LiteLLMBaseURL:      "https://litellm.example.com/",
		LiteLLMDefaultModel: "gpt-4o-mini",
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/litellm", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", w.Code)
	}

	var payload struct {
		BaseURL      string `json:"base_url"`
		DefaultModel string `json:"default_model"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if payload.BaseURL != "https://litellm.example.com/" {
		t.Fatalf("unexpected base_url: %q", payload.BaseURL)
	}
	if payload.DefaultModel != "gpt-4o-mini" {
		t.Fatalf("unexpected default_model: %q", payload.DefaultModel)
	}
}

func TestLiteLLMConfigUsesFallbackDefaults(t *testing.T) {
	h := api.NewRouter(api.Dependencies{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/litellm", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", w.Code)
	}

	var payload struct {
		BaseURL      string `json:"base_url"`
		DefaultModel string `json:"default_model"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if payload.BaseURL == "" {
		t.Fatalf("expected non-empty base_url")
	}
	if payload.DefaultModel == "" {
		t.Fatalf("expected non-empty default_model")
	}
}
