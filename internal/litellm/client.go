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

type CallRecord struct {
	At               time.Time
	Model            string
	PromptTokens     int64
	CompletionTokens int64
	TotalTokens      int64
	Cost             float64
}

type GenerateKeyInput struct {
	KeyAlias  string
	MaxBudget float64
	UserID    string
	Metadata  map[string]any
}

func (c *Client) GenerateKey(ctx context.Context, in GenerateKeyInput) (KeyRecord, error) {
	payload := map[string]any{
		"key_alias":  strings.TrimSpace(in.KeyAlias),
		"max_budget": in.MaxBudget,
	}
	if userID := strings.TrimSpace(in.UserID); userID != "" {
		payload["user_id"] = userID
	}
	if len(in.Metadata) > 0 {
		payload["metadata"] = in.Metadata
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/key/generate", payload)
	if err != nil {
		return KeyRecord{}, err
	}
	record := keyRecordFromMap(resp)
	if record.APIKey == "" {
		return KeyRecord{}, errors.New("litellm response missing api key")
	}
	return record, nil
}

type EnsureUserInput struct {
	UserID   string
	UserRole string
	Metadata map[string]any
}

func (c *Client) EnsureUser(ctx context.Context, in EnsureUserInput) error {
	userID := strings.TrimSpace(in.UserID)
	if userID == "" {
		return errors.New("user id is required")
	}
	payload := map[string]any{
		"user_id": userID,
	}
	if role := strings.TrimSpace(in.UserRole); role != "" {
		payload["user_role"] = role
	}
	if len(in.Metadata) > 0 {
		payload["metadata"] = in.Metadata
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/user/new", payload)
	if err == nil {
		return nil
	}
	if isAlreadyExistsError(err) {
		return nil
	}
	return err
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
	record := keyRecordFromMap(resp)
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
	record := keyRecordFromMap(resp)
	if record.APIKey == "" {
		record.APIKey = apiKey
	}
	if record.MaxBudget == 0 {
		record.MaxBudget = budget
	}
	return record, nil
}

func (c *Client) ListRecentCallsByKey(ctx context.Context, apiKey string, limit int) ([]CallRecord, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, errors.New("api key is required")
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	q := url.Values{}
	q.Set("api_key", apiKey)
	q.Set("key", apiKey)
	q.Set("limit", fmt.Sprintf("%d", limit))
	candidates := []string{
		"/spend/logs?" + q.Encode(),
		"/global/spend/logs?" + q.Encode(),
		"/spend_logs?" + q.Encode(),
	}
	var lastErr error
	sawNotFound := false
	for _, path := range candidates {
		data, err := c.doJSON(ctx, http.MethodGet, path, nil)
		if err != nil {
			if isNotFoundError(err) {
				sawNotFound = true
				continue
			}
			lastErr = err
			continue
		}
		records := callRecordsFromMap(data)
		if len(records) == 0 {
			continue
		}
		if len(records) > limit {
			records = records[:limit]
		}
		return records, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if sawNotFound {
		return []CallRecord{}, nil
	}
	return []CallRecord{}, nil
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
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode litellm response failed: %w", err)
	}
	data, ok := value.(map[string]any)
	if !ok {
		// Some LiteLLM endpoints return bare arrays.
		if list, ok := value.([]any); ok {
			return map[string]any{"data": list}, nil
		}
		return nil, fmt.Errorf("decode litellm response failed: unexpected json root type %T", value)
	}
	if nested, ok := asMap(data["data"]); ok {
		return nested, nil
	}
	if nested, ok := asMap(data["info"]); ok {
		return nested, nil
	}
	return data, nil
}

func keyRecordFromMap(m map[string]any) KeyRecord {
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

	budget, _ := firstNumber(m, "max_budget", "budget", "maxBudget")
	spend, _ := firstNumber(m, "spend", "spend_used", "current_spend", "total_spend")
	alias := firstString(m, "key_alias", "alias", "name")
	return KeyRecord{APIKey: apiKey, KeyAlias: alias, MaxBudget: budget, Spend: spend}
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

func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "exists") ||
		strings.Contains(msg, "duplicate") ||
		strings.Contains(msg, "conflict") ||
		strings.Contains(msg, "409")
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}

func callRecordsFromMap(m map[string]any) []CallRecord {
	items := make([]CallRecord, 0)
	candidates := []string{"data", "items", "logs", "spend_logs"}
	for _, key := range candidates {
		value, ok := m[key]
		if !ok {
			continue
		}
		rawList, ok := value.([]any)
		if !ok {
			continue
		}
		for _, raw := range rawList {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			record := CallRecord{
				At:               parseTime(entry),
				Model:            firstNonEmptyString(firstString(entry, "model", "model_name", "requested_model", "model_group"), nestedString(entry, "metadata", "model")),
				PromptTokens:     int64(firstNumberOrZero(entry, "prompt_tokens", "promptTokens", "input_tokens")),
				CompletionTokens: int64(firstNumberOrZero(entry, "completion_tokens", "completionTokens", "output_tokens")),
				TotalTokens:      int64(firstNumberOrZero(entry, "total_tokens", "totalTokens", "tokens")),
				Cost:             firstNumberOrZero(entry, "spend", "cost", "response_cost"),
			}
			if record.TotalTokens == 0 {
				record.TotalTokens = record.PromptTokens + record.CompletionTokens
			}
			items = append(items, record)
		}
	}
	return items
}

func parseTime(m map[string]any) time.Time {
	for _, key := range []string{"start_time", "created_at", "created", "timestamp"} {
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch t := value.(type) {
		case string:
			if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(t)); err == nil {
				return ts
			}
			if ts, err := time.Parse("2006-01-02T15:04:05.000000Z", strings.TrimSpace(t)); err == nil {
				return ts
			}
		case float64:
			return time.Unix(int64(t), 0).UTC()
		case int64:
			return time.Unix(t, 0).UTC()
		}
	}
	return time.Time{}
}

func firstNumberOrZero(m map[string]any, keys ...string) float64 {
	value, ok := firstNumber(m, keys...)
	if !ok {
		return 0
	}
	return value
}

func nestedString(m map[string]any, objectKey, fieldKey string) string {
	raw, ok := m[objectKey]
	if !ok || raw == nil {
		return ""
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	return firstString(obj, fieldKey)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
