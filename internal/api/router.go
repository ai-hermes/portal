package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/authn"
	"github.com/warjiang/portal/internal/authz"
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/litellm"
	"github.com/warjiang/portal/internal/litellmcredit"
	"github.com/warjiang/portal/internal/models"
)

type Dependencies struct {
	Authn               *authn.Service
	Authz               *authz.Service
	Audit               *audit.Service
	LiteLLM             *litellm.Client
	LiteLLMCredit       *litellmcredit.Service
	LiteLLMBaseURL      string
	LiteLLMDefaultModel string
}

type Router struct {
	deps Dependencies
}

const (
	principalContextKey        = "principal"
	defaultLiteLLMBaseURL      = "https://llmv2.spotty.com.cn/"
	defaultLiteLLMDefaultModel = "gpt-4o-mini"
)

func NewRouter(deps Dependencies) http.Handler {
	deps.LiteLLMBaseURL = strings.TrimSpace(deps.LiteLLMBaseURL)
	if deps.LiteLLMBaseURL == "" {
		deps.LiteLLMBaseURL = defaultLiteLLMBaseURL
	}
	deps.LiteLLMDefaultModel = strings.TrimSpace(deps.LiteLLMDefaultModel)
	if deps.LiteLLMDefaultModel == "" {
		deps.LiteLLMDefaultModel = defaultLiteLLMDefaultModel
	}

	r := &Router{deps: deps}
	engine := gin.New()
	engine.HandleMethodNotAllowed = true

	engine.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	})

	engine.GET("/healthz", r.handleHealth)
	engine.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	auth := engine.Group("/api/v1/auth")
	auth.POST("/register", r.handleRegister)
	auth.POST("/register/phone", r.handleRegisterByPhone)
	auth.POST("/sms/send-code", r.handleSendSMSCode)
	auth.POST("/verify-email", r.handleVerifyEmail)
	auth.POST("/login", r.handleLogin)
	auth.POST("/refresh", r.handleRefresh)
	auth.POST("/logout", r.handleLogout)
	auth.POST("/password/forgot", r.handleForgotPassword)
	auth.POST("/password/reset", r.handleResetPassword)
	auth.POST("/password/change", r.withAuth(), r.handleChangePassword)
	engine.GET("/api/v1/config/litellm", r.handleLiteLLMConfig)

	protected := engine.Group("/api/v1")
	protected.Use(r.withAuth())
	protected.GET("/me", r.handleMe)
	protected.POST("/permissions/check", r.handlePermissionCheck)
	protected.POST("/policies/relationships", r.handleWriteRelationships)
	protected.GET("/audit/events", r.handleAuditQuery)
	protected.GET("/tenants/:tenant_id/members", r.handleTenantMembers)
	protected.GET("/litellm/me/credit", r.handleLiteLLMMyCredit)
	protected.GET("/litellm/me/models", r.handleLiteLLMMyModels)
	protected.GET("/litellm/me/calls", r.handleLiteLLMMyCalls)
	protected.GET("/admin/litellm/credits/:tenant_id/:user_id", r.handleLiteLLMCreditGet)
	protected.POST("/admin/litellm/credits/adjust", r.handleLiteLLMCreditAdjust)
	protected.GET("/admin/litellm/events", r.handleLiteLLMCreditEvents)
	protected.GET("/admin/litellm/calls/:tenant_id/:user_id", r.handleLiteLLMRecentCalls)
	protected.GET("/admin/litellm/access", r.handleLiteLLMAccess)

	return engine
}

func (r *Router) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (r *Router) handleRegister(c *gin.Context) {
	var body registerRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	result, err := r.deps.Authn.Register(c.Request.Context(), authn.RegisterInput{
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	}, c.Request.RemoteAddr, c.Request.UserAgent())
	if err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusCreated, result)
}

type verifyEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (r *Router) handleVerifyEmail(c *gin.Context) {
	var body verifyEmailRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	err := r.deps.Authn.VerifyEmail(c.Request.Context(), authn.VerifyEmailInput{
		Email: body.Email,
		Code:  body.Code,
	})
	if err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]bool{"verified": true})
}

type loginRequest struct {
	Account  string `json:"account"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *Router) handleLogin(c *gin.Context) {
	var body loginRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	account := strings.TrimSpace(body.Account)
	if account == "" {
		account = body.Email
	}
	pair, err := r.deps.Authn.Login(c.Request.Context(), account, body.Password, c.Request.RemoteAddr, c.Request.UserAgent())
	if err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, pair)
}

type sendSMSCodeRequest struct {
	Phone   string `json:"phone"`
	Purpose string `json:"purpose"`
}

func (r *Router) handleSendSMSCode(c *gin.Context) {
	var body sendSMSCodeRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if body.Purpose == "" {
		body.Purpose = "register"
	}
	if err := r.deps.Authn.SendSMSCode(c.Request.Context(), authn.SendSMSCodeInput{
		Phone:   body.Phone,
		Purpose: body.Purpose,
	}, c.Request.RemoteAddr); err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

type registerByPhoneRequest struct {
	Phone       string `json:"phone"`
	Code        string `json:"code"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (r *Router) handleRegisterByPhone(c *gin.Context) {
	var body registerByPhoneRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	result, err := r.deps.Authn.RegisterByPhone(c.Request.Context(), authn.RegisterPhoneInput{
		Phone:       body.Phone,
		Code:        body.Code,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	}, c.Request.RemoteAddr, c.Request.UserAgent())
	if err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusCreated, result)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (r *Router) handleRefresh(c *gin.Context) {
	var body refreshRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	pair, err := r.deps.Authn.Refresh(c.Request.Context(), body.RefreshToken, c.Request.RemoteAddr, c.Request.UserAgent())
	if err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, pair)
}

func (r *Router) handleLogout(c *gin.Context) {
	var body refreshRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := r.deps.Authn.Logout(c.Request.Context(), body.RefreshToken); err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

func (r *Router) handleForgotPassword(c *gin.Context) {
	var body forgotPasswordRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := r.deps.Authn.RequestPasswordReset(c.Request.Context(), body.Email); err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (r *Router) handleResetPassword(c *gin.Context) {
	var body resetPasswordRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := r.deps.Authn.ResetPassword(c.Request.Context(), body.Token, body.NewPassword); err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (r *Router) handleChangePassword(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}

	var body changePasswordRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := r.deps.Authn.ChangePassword(c.Request.Context(), principal.UserID, body.OldPassword, body.NewPassword); err != nil {
		r.writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

func (r *Router) writeAuthError(c *gin.Context, err error) {
	if ae, ok := authn.AsAPIError(err); ok {
		c.JSON(ae.Status, map[string]any{
			"error": map[string]string{
				"code":    ae.Code,
				"message": ae.Message,
			},
		})
		return
	}
	c.JSON(http.StatusInternalServerError, map[string]any{
		"error": map[string]string{
			"code":    "internal_error",
			"message": "internal server error",
		},
	})
}

func (r *Router) withAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer"))
		if token == "" {
			c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			c.Abort()
			return
		}
		principal, err := r.deps.Authn.AuthenticateAccessToken(c.Request.Context(), token)
		if err != nil {
			r.writeAuthError(c, err)
			c.Abort()
			return
		}
		c.Set(principalContextKey, principal)
		c.Next()
	}
}

func (r *Router) handleMe(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	c.JSON(http.StatusOK, principal)
}

func (r *Router) handleLiteLLMConfig(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]string{
		"base_url":      r.deps.LiteLLMBaseURL,
		"default_model": r.deps.LiteLLMDefaultModel,
	})
}

func (r *Router) handleTenantMembers(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}

	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant id is required"})
		return
	}
	if principal.TenantID != tenantID {
		c.JSON(http.StatusForbidden, map[string]string{"error": "cross-tenant access denied"})
		return
	}

	members, err := r.deps.Authn.ListTenantMembers(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": members})
}

type checkPermissionRequest struct {
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

func (r *Router) handlePermissionCheck(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}

	var body checkPermissionRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	tuple := models.PolicyTuple{Subject: body.Subject, Relation: body.Relation, Object: body.Object}
	allowed, err := r.deps.Authz.Check(c.Request.Context(), tuple)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	_, _ = r.deps.Audit.Record(c.Request.Context(), models.AuditEvent{
		Actor:     principal.UserID,
		Action:    "permission_check",
		Resource:  body.Object,
		Result:    boolResult(allowed),
		TenantID:  principal.TenantID,
		IP:        c.Request.RemoteAddr,
		UserAgent: c.Request.UserAgent(),
		TraceID:   c.GetHeader("X-Trace-ID"),
	})

	c.JSON(http.StatusOK, map[string]bool{"allowed": allowed})
}

type writeRelationshipRequest struct {
	Tuples []models.PolicyTuple `json:"tuples"`
}

func (r *Router) handleWriteRelationships(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if principal.Role != "tenant_admin" {
		c.JSON(http.StatusForbidden, map[string]string{"error": "insufficient role"})
		return
	}

	var body writeRelationshipRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := r.deps.Authz.WriteRelationships(c.Request.Context(), body.Tuples); err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	_, _ = r.deps.Audit.Record(c.Request.Context(), models.AuditEvent{
		Actor:     principal.UserID,
		Action:    "relationship_write",
		Resource:  "policy_tuples",
		Result:    "success",
		TenantID:  principal.TenantID,
		IP:        c.Request.RemoteAddr,
		UserAgent: c.Request.UserAgent(),
		TraceID:   c.GetHeader("X-Trace-ID"),
	})

	c.JSON(http.StatusOK, map[string]any{"written": len(body.Tuples)})
}

func (r *Router) handleAuditQuery(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}

	filter := audit.QueryFilter{
		TenantID: principal.TenantID,
		Actor:    c.Query("actor"),
		Action:   c.Query("action"),
		Resource: c.Query("resource"),
	}
	events, err := r.deps.Audit.Query(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": events})
}

type liteLLMCreditAdjustRequest struct {
	TenantID string  `json:"tenant_id"`
	UserID   string  `json:"user_id"`
	Mode     string  `json:"mode"`
	Amount   float64 `json:"amount"`
	Reason   string  `json:"reason"`
}

func (r *Router) handleLiteLLMCreditGet(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if r.deps.LiteLLMCredit == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "litellm credit service is unavailable"})
		return
	}

	snapshot, err := r.deps.LiteLLMCredit.GetUserCredit(
		c.Request.Context(),
		principal,
		c.Param("tenant_id"),
		c.Param("user_id"),
	)
	if err != nil {
		r.writeLiteLLMCreditError(c, err)
		return
	}
	c.JSON(http.StatusOK, snapshot)
}

func (r *Router) handleLiteLLMCreditAdjust(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if r.deps.LiteLLMCredit == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "litellm credit service is unavailable"})
		return
	}

	var body liteLLMCreditAdjustRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snapshot, err := r.deps.LiteLLMCredit.AdjustUserCredit(c.Request.Context(), principal, litellmcredit.AdjustInput{
		TenantID: body.TenantID,
		UserID:   body.UserID,
		Mode:     body.Mode,
		Amount:   body.Amount,
		Reason:   body.Reason,
	})
	if err != nil {
		r.writeLiteLLMCreditError(c, err)
		return
	}
	c.JSON(http.StatusOK, snapshot)
}

func (r *Router) handleLiteLLMCreditEvents(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if r.deps.LiteLLMCredit == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "litellm credit service is unavailable"})
		return
	}

	limit := 50
	offset := 0
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			limit = value
		}
	}
	if raw := strings.TrimSpace(c.Query("offset")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			offset = value
		}
	}
	events, err := r.deps.LiteLLMCredit.ListEvents(c.Request.Context(), principal, limit, offset)
	if err != nil {
		r.writeLiteLLMCreditError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": events, "limit": limit, "offset": offset})
}

func (r *Router) handleLiteLLMMyCredit(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if r.deps.LiteLLMCredit == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "litellm credit service is unavailable"})
		return
	}
	snapshot, err := r.deps.LiteLLMCredit.GetMyCredit(c.Request.Context(), principal)
	if err != nil {
		r.writeLiteLLMCreditError(c, err)
		return
	}
	c.JSON(http.StatusOK, snapshot)
}

func (r *Router) handleLiteLLMMyCalls(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if r.deps.LiteLLMCredit == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "litellm credit service is unavailable"})
		return
	}
	limit := 20
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			limit = value
		}
	}
	items, err := r.deps.LiteLLMCredit.ListMyRecentCalls(c.Request.Context(), principal, limit)
	if err != nil {
		r.writeLiteLLMCreditError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": items, "limit": limit})
}

func (r *Router) handleLiteLLMMyModels(c *gin.Context) {
	if _, ok := principalFromContext(c); !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if r.deps.LiteLLM == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]any{
			"error": map[string]string{
				"code":    "service_unavailable",
				"message": "litellm service is unavailable",
			},
		})
		return
	}
	items, err := r.deps.LiteLLM.ListModels(c.Request.Context())
	if err != nil {
		r.writeLiteLLMError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (r *Router) handleLiteLLMRecentCalls(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if r.deps.LiteLLMCredit == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "litellm credit service is unavailable"})
		return
	}

	limit := 20
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			limit = value
		}
	}
	items, err := r.deps.LiteLLMCredit.ListRecentCalls(
		c.Request.Context(),
		principal,
		c.Param("tenant_id"),
		c.Param("user_id"),
		limit,
	)
	if err != nil {
		r.writeLiteLLMCreditError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": items, "limit": limit})
}

func (r *Router) handleLiteLLMAccess(c *gin.Context) {
	principal, ok := principalFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing principal"})
		return
	}
	if r.deps.LiteLLMCredit == nil {
		c.JSON(http.StatusOK, map[string]any{"can_manage": false, "service_available": false})
		return
	}
	c.JSON(http.StatusOK, map[string]any{
		"can_manage":        r.deps.LiteLLMCredit.IsPlatformAdmin(principal),
		"service_available": true,
	})
}

func (r *Router) writeLiteLLMCreditError(c *gin.Context, err error) {
	if ae, ok := litellmcredit.AsAPIError(err); ok {
		c.JSON(ae.Status, map[string]any{
			"error": map[string]string{
				"code":    ae.Code,
				"message": ae.Message,
			},
		})
		return
	}
	c.JSON(http.StatusInternalServerError, map[string]any{
		"error": map[string]string{
			"code":    "internal_error",
			"message": "internal server error",
		},
	})
}

func (r *Router) writeLiteLLMError(c *gin.Context, err error) {
	c.JSON(http.StatusBadGateway, map[string]any{
		"error": map[string]string{
			"code":    "litellm_error",
			"message": err.Error(),
		},
	})
}

func decodeJSON(c *gin.Context, dst any) error {
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func principalFromContext(c *gin.Context) (identity.Principal, bool) {
	value, ok := c.Get(principalContextKey)
	if !ok {
		return identity.Principal{}, false
	}
	principal, ok := value.(identity.Principal)
	if !ok {
		return identity.Principal{}, false
	}
	return principal, true
}

func boolResult(ok bool) string {
	if ok {
		return "success"
	}
	return "deny"
}
