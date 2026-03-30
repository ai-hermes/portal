package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "github.com/warjiang/portal/docs"
	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/authn"
	"github.com/warjiang/portal/internal/authz"
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/litellm"
	"github.com/warjiang/portal/internal/litellmcredit"
	"github.com/warjiang/portal/internal/models"
	"go.uber.org/zap"
)

type Dependencies struct {
	Authn               *authn.Service
	Authz               *authz.Service
	Audit               *audit.Service
	LiteLLM             *litellm.Client
	LiteLLMCredit       *litellmcredit.Service
	LiteLLMBaseURL      string
	LiteLLMDefaultModel string
	SwaggerEnabled      bool
	Logger              *zap.Logger
}

type Router struct {
	deps    Dependencies
	logger  *zap.Logger
	authLog *zap.Logger
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

	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	r := &Router{
		deps:    deps,
		logger:  logger,
		authLog: logger.Named("auth_http"),
	}
	engine := gin.New()
	engine.HandleMethodNotAllowed = true
	engine.Use(r.accessLogMiddleware())

	engine.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	})

	engine.GET("/healthz", r.handleHealth)
	if deps.SwaggerEnabled {
		engine.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

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

// handleHealth godoc
// @Summary Health check
// @Description Returns service health status.
// @Tags system
// @Produce json
// @Success 200 {object} statusResponse
// @Router /healthz [get]
func (r *Router) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// handleRegister godoc
// @Summary Register user by email
// @Description Registers a new user and creates a tenant.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body registerRequest true "Register payload"
// @Success 201 {object} authn.RegisterResult
// @Failure 400 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/register [post]
func (r *Router) handleRegister(c *gin.Context) {
	var body registerRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	r.authLog.Info("auth register request", zap.String("email", strings.TrimSpace(body.Email)), zap.String("remote_addr", c.Request.RemoteAddr))

	result, err := r.deps.Authn.Register(c.Request.Context(), authn.RegisterInput{
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	}, c.Request.RemoteAddr, c.Request.UserAgent())
	if err != nil {
		r.authLog.Warn("auth register failed", zap.String("email", strings.TrimSpace(body.Email)), zap.Error(err))
		r.writeAuthError(c, err)
		return
	}
	r.authLog.Info("auth register success", zap.String("email", strings.TrimSpace(body.Email)), zap.String("user_id", result.UserID), zap.String("tenant_id", result.TenantID))
	c.JSON(http.StatusCreated, result)
}

type verifyEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// handleVerifyEmail godoc
// @Summary Verify email
// @Description Verifies email with the one-time code.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body verifyEmailRequest true "Verify email payload"
// @Success 200 {object} verifiedResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/verify-email [post]
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

// handleLogin godoc
// @Summary Login
// @Description Logs in by account(email/phone) and password.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body loginRequest true "Login payload"
// @Success 200 {object} authn.TokenPair
// @Failure 400 {object} errorMessageResponse
// @Failure 401 {object} apiErrorResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/login [post]
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
	r.authLog.Info("auth login request", zap.String("account", strings.TrimSpace(account)), zap.String("remote_addr", c.Request.RemoteAddr))
	pair, err := r.deps.Authn.Login(c.Request.Context(), account, body.Password, c.Request.RemoteAddr, c.Request.UserAgent())
	if err != nil {
		r.authLog.Warn("auth login failed", zap.String("account", strings.TrimSpace(account)), zap.Error(err))
		r.writeAuthError(c, err)
		return
	}
	r.authLog.Info("auth login success", zap.String("account", strings.TrimSpace(account)))
	c.JSON(http.StatusOK, pair)
}

type sendSMSCodeRequest struct {
	Phone   string `json:"phone"`
	Purpose string `json:"purpose"`
}

// handleSendSMSCode godoc
// @Summary Send SMS code
// @Description Sends an SMS verification code for a given purpose.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body sendSMSCodeRequest true "Send SMS code payload"
// @Success 200 {object} okResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 429 {object} apiErrorResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/sms/send-code [post]
func (r *Router) handleSendSMSCode(c *gin.Context) {
	var body sendSMSCodeRequest
	if err := decodeJSON(c, &body); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if body.Purpose == "" {
		body.Purpose = "register"
	}
	r.authLog.Info("auth send sms code request", zap.String("phone", strings.TrimSpace(body.Phone)), zap.String("purpose", strings.TrimSpace(body.Purpose)), zap.String("remote_addr", c.Request.RemoteAddr))
	if err := r.deps.Authn.SendSMSCode(c.Request.Context(), authn.SendSMSCodeInput{
		Phone:   body.Phone,
		Purpose: body.Purpose,
	}, c.Request.RemoteAddr); err != nil {
		r.authLog.Warn("auth send sms code failed", zap.String("phone", strings.TrimSpace(body.Phone)), zap.String("purpose", strings.TrimSpace(body.Purpose)), zap.Error(err))
		r.writeAuthError(c, err)
		return
	}
	r.authLog.Info("auth send sms code success", zap.String("phone", strings.TrimSpace(body.Phone)), zap.String("purpose", strings.TrimSpace(body.Purpose)))
	c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

type registerByPhoneRequest struct {
	Phone       string `json:"phone"`
	Code        string `json:"code"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// handleRegisterByPhone godoc
// @Summary Register user by phone
// @Description Registers a new user with phone and SMS code.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body registerByPhoneRequest true "Register by phone payload"
// @Success 201 {object} authn.RegisterResult
// @Failure 400 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/register/phone [post]
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

// handleRefresh godoc
// @Summary Refresh token pair
// @Description Exchanges refresh token for a new access/refresh pair.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body refreshRequest true "Refresh payload"
// @Success 200 {object} authn.TokenPair
// @Failure 400 {object} errorMessageResponse
// @Failure 401 {object} apiErrorResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/refresh [post]
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

// handleLogout godoc
// @Summary Logout
// @Description Revokes the given refresh token.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body refreshRequest true "Logout payload"
// @Success 200 {object} okResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/logout [post]
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

// handleForgotPassword godoc
// @Summary Request password reset
// @Description Sends password reset token to the email.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body forgotPasswordRequest true "Forgot password payload"
// @Success 200 {object} okResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/password/forgot [post]
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

// handleResetPassword godoc
// @Summary Reset password
// @Description Resets password with password-reset token.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body resetPasswordRequest true "Reset password payload"
// @Success 200 {object} okResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/password/reset [post]
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

// handleChangePassword godoc
// @Summary Change password
// @Description Changes current user's password.
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param request body changePasswordRequest true "Change password payload"
// @Success 200 {object} okResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 401 {object} apiErrorResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/auth/password/change [post]
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

// handleMe godoc
// @Summary Current principal
// @Description Returns current authenticated principal.
// @Tags user
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} identity.Principal
// @Failure 401 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/me [get]
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

// handleTenantMembers godoc
// @Summary List tenant members
// @Description Lists members of the requested tenant.
// @Tags user
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {object} tenantMembersResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 403 {object} errorMessageResponse
// @Failure 500 {object} errorMessageResponse
// @Router /api/v1/tenants/{tenant_id}/members [get]
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

// handlePermissionCheck godoc
// @Summary Check permission
// @Description Checks whether a subject has relation on object.
// @Tags authz
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param request body checkPermissionRequest true "Permission check payload"
// @Success 200 {object} allowedResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 500 {object} errorMessageResponse
// @Router /api/v1/permissions/check [post]
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

// handleWriteRelationships godoc
// @Summary Write policy relationships
// @Description Writes relationship tuples (tenant_admin only).
// @Tags authz
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param request body writeRelationshipRequest true "Relationship tuples payload"
// @Success 200 {object} writtenResponse
// @Failure 400 {object} errorMessageResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 403 {object} errorMessageResponse
// @Failure 500 {object} errorMessageResponse
// @Router /api/v1/policies/relationships [post]
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

// handleAuditQuery godoc
// @Summary Query audit events
// @Description Queries tenant audit events with optional filters.
// @Tags audit
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param actor query string false "Actor user id"
// @Param action query string false "Action"
// @Param resource query string false "Resource"
// @Success 200 {object} auditEventsResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 500 {object} errorMessageResponse
// @Router /api/v1/audit/events [get]
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

// handleLiteLLMCreditGet godoc
// @Summary Get user credit (admin)
// @Description Gets LiteLLM credit snapshot for tenant user (platform admin only).
// @Tags litellm
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} litellmcredit.CreditSnapshot
// @Failure 401 {object} errorMessageResponse
// @Failure 403 {object} apiErrorResponse
// @Failure 503 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/admin/litellm/credits/{tenant_id}/{user_id} [get]
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

// handleLiteLLMCreditAdjust godoc
// @Summary Adjust user credit (admin)
// @Description Adjusts LiteLLM credit by set/delta (platform admin only).
// @Tags litellm
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param request body liteLLMCreditAdjustRequest true "Adjust credit payload"
// @Success 200 {object} litellmcredit.CreditSnapshot
// @Failure 400 {object} errorMessageResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 403 {object} apiErrorResponse
// @Failure 503 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/admin/litellm/credits/adjust [post]
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

// handleLiteLLMCreditEvents godoc
// @Summary List credit events (admin)
// @Description Lists LiteLLM credit adjustment events (platform admin only).
// @Tags litellm
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param limit query int false "Page size"
// @Param offset query int false "Page offset"
// @Success 200 {object} liteLLMEventsResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 403 {object} apiErrorResponse
// @Failure 503 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/admin/litellm/events [get]
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

// handleLiteLLMMyCredit godoc
// @Summary Get my credit
// @Description Gets authenticated user's LiteLLM credit snapshot.
// @Tags litellm
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} litellmcredit.CreditSnapshot
// @Failure 401 {object} errorMessageResponse
// @Failure 503 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/litellm/me/credit [get]
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

// handleLiteLLMMyCalls godoc
// @Summary List my recent calls
// @Description Lists recent LiteLLM calls for current user.
// @Tags litellm
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param limit query int false "Max number of records"
// @Success 200 {object} liteLLMRecentCallsResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 503 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/litellm/me/calls [get]
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

// handleLiteLLMRecentCalls godoc
// @Summary List user recent calls (admin)
// @Description Lists recent LiteLLM calls for a tenant user (platform admin only).
// @Tags litellm
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Param limit query int false "Max number of records"
// @Success 200 {object} liteLLMRecentCallsResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 403 {object} apiErrorResponse
// @Failure 503 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/admin/litellm/calls/{tenant_id}/{user_id} [get]
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

// handleLiteLLMAccess godoc
// @Summary LiteLLM access info
// @Description Returns whether current user can manage LiteLLM credit.
// @Tags litellm
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} liteLLMAccessResponse
// @Failure 401 {object} errorMessageResponse
// @Failure 500 {object} apiErrorResponse
// @Router /api/v1/admin/litellm/access [get]
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

func (r *Router) accessLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("path", c.FullPath()),
			zap.String("raw_path", c.Request.URL.Path),
			zap.Int("status", status),
			zap.Int64("latency_ms", latency.Milliseconds()),
			zap.String("client_ip", c.ClientIP()),
			zap.String("remote_addr", c.Request.RemoteAddr),
			zap.String("user_agent", c.Request.UserAgent()),
		}
		if reqID := c.GetHeader("X-Request-Id"); reqID != "" {
			fields = append(fields, zap.String("request_id", reqID))
		}

		switch {
		case status >= http.StatusInternalServerError:
			r.logger.Error("http request", fields...)
		case status >= http.StatusBadRequest:
			r.logger.Warn("http request", fields...)
		default:
			r.logger.Info("http request", fields...)
		}
	}
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
