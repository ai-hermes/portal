package authzopenfga

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/warjiang/portal/internal/models"
)

type Provider struct {
	apiURL  string
	storeID string
	client  *http.Client
}

func NewProvider(apiURL, storeID string) *Provider {
	return &Provider{
		apiURL:  strings.TrimRight(apiURL, "/"),
		storeID: storeID,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *Provider) Check(ctx context.Context, tuple models.PolicyTuple) (bool, error) {
	payload := map[string]any{
		"tuple_key": map[string]string{
			"user":     tuple.Subject,
			"relation": tuple.Relation,
			"object":   tuple.Object,
		},
	}
	var res struct {
		Allowed bool `json:"allowed"`
	}
	if err := p.postJSON(ctx, fmt.Sprintf("/stores/%s/check", p.storeID), payload, &res); err != nil {
		return false, err
	}
	return res.Allowed, nil
}

func (p *Provider) WriteRelationships(ctx context.Context, tuples []models.PolicyTuple) error {
	writes := make([]map[string]map[string]string, 0, len(tuples))
	for _, t := range tuples {
		writes = append(writes, map[string]map[string]string{
			"tuple_key": {
				"user":     t.Subject,
				"relation": t.Relation,
				"object":   t.Object,
			},
		})
	}
	payload := map[string]any{"writes": writes}
	return p.postJSON(ctx, fmt.Sprintf("/stores/%s/write", p.storeID), payload, nil)
}

func (p *Provider) postJSON(ctx context.Context, path string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("openfga request failed: %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return err
	}
	return nil
}
