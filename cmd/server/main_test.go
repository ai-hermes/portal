package main

import "testing"

func TestResolveLiteLLMRuntimeConfigDefaults(t *testing.T) {
	t.Setenv("LITELLM_BASE_URL", "")
	t.Setenv("LITELLM_DEFAULT_MODEL", "")

	cfg := resolveLiteLLMRuntimeConfig()
	if cfg.BaseURL != defaultLiteLLMBaseURL {
		t.Fatalf("expected default base url %q, got %q", defaultLiteLLMBaseURL, cfg.BaseURL)
	}
	if cfg.DefaultModel != defaultLiteLLMDefaultModel {
		t.Fatalf("expected default model %q, got %q", defaultLiteLLMDefaultModel, cfg.DefaultModel)
	}
}

func TestResolveLiteLLMRuntimeConfigFromEnv(t *testing.T) {
	t.Setenv("LITELLM_BASE_URL", " https://llm.internal/ ")
	t.Setenv("LITELLM_DEFAULT_MODEL", " gpt-4.1-mini ")

	cfg := resolveLiteLLMRuntimeConfig()
	if cfg.BaseURL != "https://llm.internal/" {
		t.Fatalf("unexpected base url %q", cfg.BaseURL)
	}
	if cfg.DefaultModel != "gpt-4.1-mini" {
		t.Fatalf("unexpected default model %q", cfg.DefaultModel)
	}
}
