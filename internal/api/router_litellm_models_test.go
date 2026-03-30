package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/litellm"
)

func TestHandleLiteLLMMyModelsServiceUnavailable(t *testing.T) {
	t.Parallel()

	recorder, c := newLiteLLMModelContext(http.MethodGet, "/api/v1/litellm/me/models")
	r := &Router{deps: Dependencies{}}

	r.handleLiteLLMMyModels(c)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", recorder.Code)
	}
}

func TestHandleLiteLLMMyModelsBadGateway(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream failed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := litellm.NewClient(litellm.Config{
		BaseURL:    srv.URL,
		MasterKey:  "test-master-key",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("new litellm client failed: %v", err)
	}

	recorder, c := newLiteLLMModelContext(http.MethodGet, "/api/v1/litellm/me/models")
	r := &Router{deps: Dependencies{LiteLLM: client}}

	r.handleLiteLLMMyModels(c)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", recorder.Code)
	}

	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if payload.Error.Code != "litellm_error" {
		t.Fatalf("expected error code litellm_error, got %q", payload.Error.Code)
	}
}

func TestHandleLiteLLMMyModelsSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data":[
				{"id":"gpt-4o","owned_by":"openai","context_window":128000}
			]
		}`))
	}))
	defer srv.Close()

	client, err := litellm.NewClient(litellm.Config{
		BaseURL:    srv.URL,
		MasterKey:  "test-master-key",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("new litellm client failed: %v", err)
	}

	recorder, c := newLiteLLMModelContext(http.MethodGet, "/api/v1/litellm/me/models")
	r := &Router{deps: Dependencies{LiteLLM: client}}

	r.handleLiteLLMMyModels(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload struct {
		Items []litellm.ModelInfo `json:"items"`
		Total int                 `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if payload.Total != 1 || len(payload.Items) != 1 {
		t.Fatalf("unexpected payload: total=%d len=%d", payload.Total, len(payload.Items))
	}
	if payload.Items[0].ID != "gpt-4o" || payload.Items[0].Provider != "openai" || payload.Items[0].ContextWindow != 128000 {
		t.Fatalf("unexpected model: %+v", payload.Items[0])
	}
}

func newLiteLLMModelContext(method, path string) (*httptest.ResponseRecorder, *gin.Context) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(method, path, nil)
	c.Set(principalContextKey, identity.Principal{
		TenantID: "tenant-1",
		UserID:   "user-1",
		Email:    "user@example.com",
	})
	return recorder, c
}
