package api

import (
	"net/http"
	"strings"

	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/authn"
	"github.com/warjiang/portal/internal/authz"
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/models"
	"github.com/warjiang/portal/internal/utils"
)

type Dependencies struct {
	Authn *authn.Service
	Authz *authz.Service
	Audit *audit.Service
}

type Router struct {
	deps Dependencies
}

func NewRouter(deps Dependencies) http.Handler {
	r := &Router{deps: deps}
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", r.handleHealth)
	mux.HandleFunc("/api/v1/auth/register", r.handleRegister)
	mux.HandleFunc("/api/v1/auth/verify-email", r.handleVerifyEmail)
	mux.HandleFunc("/api/v1/auth/login", r.handleLogin)
	mux.HandleFunc("/api/v1/auth/refresh", r.handleRefresh)
	mux.HandleFunc("/api/v1/auth/logout", r.handleLogout)
	mux.HandleFunc("/api/v1/auth/password/change", r.withAuth(r.handleChangePassword))
	mux.HandleFunc("/api/v1/auth/password/forgot", r.handleForgotPassword)
	mux.HandleFunc("/api/v1/auth/password/reset", r.handleResetPassword)
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

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (r *Router) handleRegister(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body registerRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	result, err := r.deps.Authn.Register(req.Context(), authn.RegisterInput{
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	}, req.RemoteAddr, req.UserAgent())
	if err != nil {
		r.writeAuthError(w, err)
		return
	}
	utils.JSON(w, http.StatusCreated, result)
}

type verifyEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (r *Router) handleVerifyEmail(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body verifyEmailRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	err := r.deps.Authn.VerifyEmail(req.Context(), authn.VerifyEmailInput{
		Email: body.Email,
		Code:  body.Code,
	})
	if err != nil {
		r.writeAuthError(w, err)
		return
	}
	utils.JSON(w, http.StatusOK, map[string]bool{"verified": true})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *Router) handleLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body loginRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	pair, err := r.deps.Authn.Login(req.Context(), body.Email, body.Password, req.RemoteAddr, req.UserAgent())
	if err != nil {
		r.writeAuthError(w, err)
		return
	}
	utils.JSON(w, http.StatusOK, pair)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (r *Router) handleRefresh(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body refreshRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	pair, err := r.deps.Authn.Refresh(req.Context(), body.RefreshToken, req.RemoteAddr, req.UserAgent())
	if err != nil {
		r.writeAuthError(w, err)
		return
	}
	utils.JSON(w, http.StatusOK, pair)
}

func (r *Router) handleLogout(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body refreshRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := r.deps.Authn.Logout(req.Context(), body.RefreshToken); err != nil {
		r.writeAuthError(w, err)
		return
	}
	utils.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

func (r *Router) handleForgotPassword(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body forgotPasswordRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := r.deps.Authn.RequestPasswordReset(req.Context(), body.Email); err != nil {
		r.writeAuthError(w, err)
		return
	}
	utils.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (r *Router) handleResetPassword(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body resetPasswordRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := r.deps.Authn.ResetPassword(req.Context(), body.Token, body.NewPassword); err != nil {
		r.writeAuthError(w, err)
		return
	}
	utils.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (r *Router) handleChangePassword(w http.ResponseWriter, req *http.Request, principal identity.Principal) {
	if req.Method != http.MethodPost {
		utils.JSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body changePasswordRequest
	if err := utils.DecodeJSON(req, &body); err != nil {
		utils.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := r.deps.Authn.ChangePassword(req.Context(), principal.UserID, body.OldPassword, body.NewPassword); err != nil {
		r.writeAuthError(w, err)
		return
	}
	utils.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (r *Router) writeAuthError(w http.ResponseWriter, err error) {
	if ae, ok := authn.AsAPIError(err); ok {
		utils.JSON(w, ae.Status, map[string]any{
			"error": map[string]string{
				"code":    ae.Code,
				"message": ae.Message,
			},
		})
		return
	}
	utils.JSON(w, http.StatusInternalServerError, map[string]any{
		"error": map[string]string{
			"code":    "internal_error",
			"message": "internal server error",
		},
	})
}

func (r *Router) withAuth(next func(http.ResponseWriter, *http.Request, identity.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer"))
		if token == "" {
			utils.JSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		principal, err := r.deps.Authn.AuthenticateAccessToken(req.Context(), token)
		if err != nil {
			r.writeAuthError(w, err)
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
	members, err := r.deps.Authn.ListTenantMembers(req.Context(), tenantID)
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
