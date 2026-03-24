package api

import (
	"net/http"
	"strings"

	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/auth"
	"github.com/warjiang/portal/internal/authz"
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/models"
	"github.com/warjiang/portal/internal/utils"
)

type Dependencies struct {
	Auth     *auth.Service
	Identity *identity.Service
	Authz    *authz.Service
	Audit    *audit.Service
}

type Router struct {
	deps Dependencies
}

func NewRouter(deps Dependencies) http.Handler {
	r := &Router{deps: deps}
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", r.handleHealth)
	mux.HandleFunc("/api/v1/auth/login/start", r.handleLoginStart)
	mux.HandleFunc("/api/v1/auth/callback", r.handleAuthCallback)
	mux.HandleFunc("/api/v1/me", r.withAuth(r.handleMe))
	mux.HandleFunc("/api/v1/permissions/check", r.withAuth(r.handlePermissionCheck))
	mux.HandleFunc("/api/v1/policies/relationships", r.withAuth(r.handleWriteRelationships))
	mux.HandleFunc("/api/v1/audit/events", r.withAuth(r.handleAuditQuery))
	mux.HandleFunc("/api/v1/tenants/", r.withAuth(r.handleTenantMembers))

	return mux
}

func (r *Router) handleHealth(w http.ResponseWriter, _ *http.Request) {
	utils.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginStartRequest struct {
	TenantID    string `json:"tenant_id"`
	RedirectURI string `json:"redirect_uri"`
}

func (r *Router) handleLoginStart(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body loginStartRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	authURL, state, err := r.deps.Auth.StartLogin(req.Context(), body.TenantID, body.RedirectURI)
	if err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	utils.JSON(w, http.StatusOK, map[string]string{"auth_url": authURL, "state": state})
}

func (r *Router) handleAuthCallback(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")
	token, err := r.deps.Auth.HandleCallback(req.Context(), code, state)
	if err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	utils.JSON(w, http.StatusOK, map[string]string{"access_token": token, "token_type": "Bearer"})
}

func (r *Router) withAuth(next func(http.ResponseWriter, *http.Request, identity.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer"))
		if token == "" {
			utils.JSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		principal, err := r.deps.Identity.ResolvePrincipal(req.Context(), token)
		if err != nil {
			utils.JSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		next(w, req, principal)
	}
}

func (r *Router) handleMe(w http.ResponseWriter, req *http.Request, principal identity.Principal) {
	if req.Method != http.MethodGet {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	utils.JSON(w, http.StatusOK, principal)
}

func (r *Router) handleTenantMembers(w http.ResponseWriter, req *http.Request, principal identity.Principal) {
	if req.Method != http.MethodGet {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	prefix := "/api/v1/tenants/"
	if !strings.HasPrefix(req.URL.Path, prefix) || !strings.HasSuffix(req.URL.Path, "/members") {
		utils.JSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	tenantID := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, prefix), "/members")
	if tenantID == "" {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": "tenant id is required"})
		return
	}
	if principal.TenantID != tenantID {
		utils.JSON(w, http.StatusForbidden, map[string]string{"error": "cross-tenant access denied"})
		return
	}
	members, err := r.deps.Identity.ListTenantMembers(req.Context(), tenantID)
	if err != nil {
		utils.JSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	utils.JSON(w, http.StatusOK, map[string]any{"items": members})
}

type checkPermissionRequest struct {
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

func (r *Router) handlePermissionCheck(w http.ResponseWriter, req *http.Request, principal identity.Principal) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body checkPermissionRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	tuple := models.PolicyTuple{Subject: body.Subject, Relation: body.Relation, Object: body.Object}
	allowed, err := r.deps.Authz.Check(req.Context(), tuple)
	if err != nil {
		utils.JSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	_, _ = r.deps.Audit.Record(req.Context(), models.AuditEvent{
		Actor:     principal.UserID,
		Action:    "permission_check",
		Resource:  body.Object,
		Result:    boolResult(allowed),
		TenantID:  principal.TenantID,
		IP:        req.RemoteAddr,
		UserAgent: req.UserAgent(),
		TraceID:   req.Header.Get("X-Trace-ID"),
	})

	utils.JSON(w, http.StatusOK, map[string]bool{"allowed": allowed})
}

type writeRelationshipRequest struct {
	Tuples []models.PolicyTuple `json:"tuples"`
}

func (r *Router) handleWriteRelationships(w http.ResponseWriter, req *http.Request, principal identity.Principal) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if principal.Role != "tenant_admin" {
		utils.JSON(w, http.StatusForbidden, map[string]string{"error": "insufficient role"})
		return
	}

	var body writeRelationshipRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := r.deps.Authz.WriteRelationships(req.Context(), body.Tuples); err != nil {
		utils.JSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	_, _ = r.deps.Audit.Record(req.Context(), models.AuditEvent{
		Actor:     principal.UserID,
		Action:    "relationship_write",
		Resource:  "policy_tuples",
		Result:    "success",
		TenantID:  principal.TenantID,
		IP:        req.RemoteAddr,
		UserAgent: req.UserAgent(),
		TraceID:   req.Header.Get("X-Trace-ID"),
	})

	utils.JSON(w, http.StatusOK, map[string]any{"written": len(body.Tuples)})
}

func (r *Router) handleAuditQuery(w http.ResponseWriter, req *http.Request, principal identity.Principal) {
	if req.Method != http.MethodGet {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	filter := audit.QueryFilter{
		TenantID: principal.TenantID,
		Actor:    req.URL.Query().Get("actor"),
		Action:   req.URL.Query().Get("action"),
		Resource: req.URL.Query().Get("resource"),
	}
	events, err := r.deps.Audit.Query(req.Context(), filter)
	if err != nil {
		utils.JSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	utils.JSON(w, http.StatusOK, map[string]any{"items": events})
}

func boolResult(ok bool) string {
	if ok {
		return "success"
	}
	return "deny"
}
