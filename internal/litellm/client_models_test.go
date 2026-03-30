package litellm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientListModelsPrimaryEndpoint(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-master-key" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"object":"list",
			"data":[
				{"id":"gpt-4o","owned_by":"openai","context_window":128000},
				{"model_name":"claude-3-5-sonnet","litellm_provider":"anthropic","model_info":{"max_input_tokens":200000}}
			]
		}`))
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		BaseURL:    srv.URL,
		MasterKey:  "test-master-key",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	items, err := client.ListModels(context.Background())
	if err != nil {
		t.Fatalf("list models failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 models, got %d", len(items))
	}
	if items[0].ID != "gpt-4o" || items[0].ModelName != "gpt-4o" || items[0].Provider != "openai" || items[0].ContextWindow != 128000 {
		t.Fatalf("unexpected first model: %+v", items[0])
	}
	if items[1].ID != "claude-3-5-sonnet" || items[1].Provider != "anthropic" || items[1].ContextWindow != 200000 {
		t.Fatalf("unexpected second model: %+v", items[1])
	}
}

func TestClientListModelsFallbackEndpoint(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			http.NotFound(w, r)
		case "/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"models":{
					"qwen-plus":{"provider":"openrouter","context_window":"32768"}
				}
			}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		BaseURL:    srv.URL,
		MasterKey:  "test-master-key",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	items, err := client.ListModels(context.Background())
	if err != nil {
		t.Fatalf("list models failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 model, got %d", len(items))
	}
	if items[0].ID != "qwen-plus" || items[0].ModelName != "qwen-plus" || items[0].Provider != "openrouter" || items[0].ContextWindow != 32768 {
		t.Fatalf("unexpected model: %+v", items[0])
	}
}

func TestClientListModelsReturnsEmptyWhenNotFound(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		BaseURL:    srv.URL,
		MasterKey:  "test-master-key",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	items, err := client.ListModels(context.Background())
	if err != nil {
		t.Fatalf("list models failed: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 models, got %d", len(items))
	}
}

func TestClientListModelsReturnsError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream broken", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		BaseURL:    srv.URL,
		MasterKey:  "test-master-key",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	_, err = client.ListModels(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
