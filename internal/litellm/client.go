package litellm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	BaseURL    string
	MasterKey  string
	HTTPClient *http.Client
}

type Client struct {
	baseURL   string
	masterKey string
	http      *http.Client
}

func NewClient(cfg Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("litellm base url is required")
	}
	masterKey := strings.TrimSpace(cfg.MasterKey)
	if masterKey == "" {
		return nil, errors.New("litellm master key is required")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{baseURL: baseURL, masterKey: masterKey, http: httpClient}, nil
}

type KeyRecord struct {
	APIKey    string
	KeyAlias  string
	MaxBudget float64
	Spend     float64
}

type GenerateKeyInput struct {
	KeyAlias  string
	MaxBudget float64
	Metadata  map[string]any
}

func (c *Client) GenerateKey(ctx context.Context, in GenerateKeyInput) (KeyRecord, error) {
	payload := map[string]any{
		"key_alias":  strings.TrimSpace(in.KeyAlias),
		"max_budget": in.MaxBudget,
	}
	if len(in.Metadata) > 0 {
		payload["metadata"] = in.Metadata
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/key/generate", payload)
	if err != nil {
		return KeyRecord{}, err
	}
	return keyRecordFromMap(resp)
}

func (c *Client) GetKeyInfo(ctx context.Context, apiKey string) (KeyRecord, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return KeyRecord{}, errors.New("api key is required")
	}
	q := url.Values{}
	q.Set("key", apiKey)
	resp, err := c.doJSON(ctx, http.MethodGet, "/key/info?"+q.Encode(), nil)
	if err != nil {
		return KeyRecord{}, err
	}
	record, err := keyRecordFromMap(resp)
	if err != nil {
		return KeyRecord{}, err
	}
	if record.APIKey == "" {
		record.APIKey = apiKey
	}
	return record, nil
}

func (c *Client) UpdateKeyBudget(ctx context.Context, apiKey string, budget float64) (KeyRecord, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return KeyRecord{}, errors.New("api key is required")
	}
	if math.IsNaN(budget) || math.IsInf(budget, 0) || budget < 0 {
		return KeyRecord{}, errors.New("budget must be a finite number and >= 0")
	}
	payload := map[string]any{
		"key":        apiKey,
		"max_budget": budget,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/key/update", payload)
	if err != nil {
		return KeyRecord{}, err
	}
	record, err := keyRecordFromMap(resp)
	if err != nil {
		return KeyRecord{}, err
	}
	if record.APIKey == "" {
		record.APIKey = apiKey
	}
	if record.MaxBudget == 0 {
		record.MaxBudget = budget
	}
	return record, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, payload any) (map[string]any, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.masterKey)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("litellm request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("litellm error (%d): %s", resp.StatusCode, msg)
	}

	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("decode litellm response failed: %w", err)
	}
	if nested, ok := asMap(data["data"]); ok {
		return nested, nil
	}
	if nested, ok := asMap(data["info"]); ok {
		return nested, nil
	}
	return data, nil
}

func keyRecordFromMap(m map[string]any) (KeyRecord, error) {
	apiKey := firstString(m,
		"key",
		"api_key",
		"token",
	)
	if nested, ok := asMap(m["key_info"]); ok {
		if apiKey == "" {
			apiKey = firstString(nested, "key", "api_key", "token")
		}
		if alias := firstString(m, "key_alias", "alias", "name"); alias == "" {
			m["key_alias"] = firstString(nested, "key_alias", "alias", "name")
		}
		if _, ok := firstNumber(m, "max_budget", "budget", "maxBudget"); !ok {
			if n, ok := firstNumber(nested, "max_budget", "budget", "maxBudget"); ok {
				m["max_budget"] = n
			}
		}
		if _, ok := firstNumber(m, "spend", "spend_used", "current_spend", "total_spend"); !ok {
			if n, ok := firstNumber(nested, "spend", "spend_used", "current_spend", "total_spend"); ok {
				m["spend"] = n
			}
		}
	}

	if apiKey == "" {
		return KeyRecord{}, errors.New("litellm response missing api key")
	}
	budget, _ := firstNumber(m, "max_budget", "budget", "maxBudget")
	spend, _ := firstNumber(m, "spend", "spend_used", "current_spend", "total_spend")
	alias := firstString(m, "key_alias", "alias", "name")
	return KeyRecord{APIKey: apiKey, KeyAlias: alias, MaxBudget: budget, Spend: spend}, nil
}

func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				return strings.TrimSpace(t)
			}
		}
	}
	return ""
}

func firstNumber(m map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case float64:
			if !math.IsNaN(t) && !math.IsInf(t, 0) {
				return t, true
			}
		case float32:
			f := float64(t)
			if !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f, true
			}
		case int:
			return float64(t), true
		case int64:
			return float64(t), true
		case json.Number:
			f, err := t.Float64()
			if err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f, true
			}
		case string:
			f, err := json.Number(strings.TrimSpace(t)).Float64()
			if err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f, true
			}
		}
	}
	return 0, false
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}
