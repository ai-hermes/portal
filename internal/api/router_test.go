package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/warjiang/portal/internal/api"
	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/auth"
	"github.com/warjiang/portal/internal/authz"
	identitysvc "github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/models"
	"github.com/warjiang/portal/internal/providers/auditmem"
	"github.com/warjiang/portal/internal/providers/authzmem"
	"github.com/warjiang/portal/internal/providers/identitymem"
)

func setupHandler() http.Handler {
	idp := identitymem.NewProvider()
	auditSvc := audit.NewService(auditmem.NewStore())
	authzSvc := authz.NewService(authzmem.NewProvider())
	return api.NewRouter(api.Dependencies{
		Auth:     auth.NewService(idp),
		Identity: identitysvc.NewService(idp),
		Authz:    authzSvc,
		Audit:    auditSvc,
	})
}

func TestCrossTenantMembersDenied(t *testing.T) {
	h := setupHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-other/members", nil)
	req.Header.Set("Authorization", "Bearer dev:tenant-acme:u-admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 got %d", w.Code)
	}
}

func TestWriteAndCheckPermission(t *testing.T) {
	h := setupHandler()

	writeBody := map[string]any{"tuples": []models.PolicyTuple{{Subject: "u-admin", Relation: "viewer", Object: "project:alpha"}}}
	buf, _ := json.Marshal(writeBody)
	writeReq := httptest.NewRequest(http.MethodPost, "/api/v1/policies/relationships", bytes.NewReader(buf))
	writeReq.Header.Set("Authorization", "Bearer dev:tenant-acme:u-admin")
	writeReq.Header.Set("Content-Type", "application/json")
	writeRes := httptest.NewRecorder()
	h.ServeHTTP(writeRes, writeReq)
	if writeRes.Code != http.StatusOK {
		t.Fatalf("write failed %d", writeRes.Code)
	}

	checkBody := map[string]string{"subject": "u-admin", "relation": "viewer", "object": "project:alpha"}
	cbuf, _ := json.Marshal(checkBody)
	checkReq := httptest.NewRequest(http.MethodPost, "/api/v1/permissions/check", bytes.NewReader(cbuf))
	checkReq.Header.Set("Authorization", "Bearer dev:tenant-acme:u-admin")
	checkReq.Header.Set("Content-Type", "application/json")
	checkRes := httptest.NewRecorder()
	h.ServeHTTP(checkRes, checkReq)
	if checkRes.Code != http.StatusOK {
		t.Fatalf("check failed %d", checkRes.Code)
	}

	var payload map[string]bool
	_ = json.Unmarshal(checkRes.Body.Bytes(), &payload)
	if !payload["allowed"] {
		t.Fatalf("expected allowed=true")
	}
}

func TestNonAdminCannotWriteRelationships(t *testing.T) {
	h := setupHandler()
	writeBody := map[string]any{"tuples": []models.PolicyTuple{{Subject: "u-viewer", Relation: "viewer", Object: "project:alpha"}}}
	buf, _ := json.Marshal(writeBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/relationships", bytes.NewReader(buf))
	req.Header.Set("Authorization", "Bearer dev:tenant-acme:u-viewer")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 got %d", w.Code)
	}
}

func TestAuditEventsGenerated(t *testing.T) {
	h := setupHandler()
	checkBody := map[string]string{"subject": "u-admin", "relation": "owner", "object": "project:alpha"}
	buf, _ := json.Marshal(checkBody)
	checkReq := httptest.NewRequest(http.MethodPost, "/api/v1/permissions/check", bytes.NewReader(buf))
	checkReq.Header.Set("Authorization", "Bearer dev:tenant-acme:u-admin")
	checkReq.Header.Set("Content-Type", "application/json")
	checkRes := httptest.NewRecorder()
	h.ServeHTTP(checkRes, checkReq)
	if checkRes.Code != http.StatusOK {
		t.Fatalf("check failed %d", checkRes.Code)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
	listReq.Header.Set("Authorization", "Bearer dev:tenant-acme:u-admin")
	listRes := httptest.NewRecorder()
	h.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("audit list failed %d", listRes.Code)
	}

	var payload struct {
		Items []models.AuditEvent `json:"items"`
	}
	_ = json.Unmarshal(listRes.Body.Bytes(), &payload)
	if len(payload.Items) == 0 {
		t.Fatalf("expected audit events")
	}
	if payload.Items[0].ID == 0 {
		t.Fatalf("expected immutable id")
	}
}
