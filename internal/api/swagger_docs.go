package api

import (
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/litellm"
	"github.com/warjiang/portal/internal/litellmcredit"
	"github.com/warjiang/portal/internal/models"
)

type swaggerStatusResponse struct {
	Status string `json:"status"`
}

type swaggerOKResponse struct {
	OK bool `json:"ok"`
}

type swaggerVerifiedResponse struct {
	Verified bool `json:"verified"`
}

type swaggerAllowedResponse struct {
	Allowed bool `json:"allowed"`
}

type swaggerWrittenResponse struct {
	Written int `json:"written"`
}

type swaggerSimpleErrorResponse struct {
	Error string `json:"error"`
}

type swaggerErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type swaggerAPIErrorResponse struct {
	Error swaggerErrorBody `json:"error"`
}

type swaggerMemberListResponse struct {
	Items []identity.Principal `json:"items"`
}

type swaggerAuditListResponse struct {
	Items []models.AuditEvent `json:"items"`
}

type swaggerLiteLLMConfigResponse struct {
	BaseURL      string `json:"base_url"`
	DefaultModel string `json:"default_model"`
}

type swaggerLiteLLMEventListResponse struct {
	Items  []litellmcredit.CreditEvent `json:"items"`
	Limit  int                         `json:"limit"`
	Offset int                         `json:"offset"`
}

type swaggerLiteLLMCallListResponse struct {
	Items []litellmcredit.RecentCall `json:"items"`
	Limit int                        `json:"limit"`
}

type swaggerLiteLLMModelListResponse struct {
	Items []litellm.ModelInfo `json:"items"`
	Total int                 `json:"total"`
}

type swaggerLiteLLMAccessResponse struct {
	CanManage        bool `json:"can_manage"`
	ServiceAvailable bool `json:"service_available"`
}

// healthzDoc godoc
// @Summary Health check
// @Tags system
// @Produce json
// @Success 200 {object} swaggerStatusResponse
// @Router /healthz [get]
func healthzDoc() {}

// registerDoc godoc
// @Summary Register by email
// @Tags auth
// @Accept json
// @Produce json
// @Param body body registerRequest true "Register payload"
// @Success 201 {object} authn.RegisterResult
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 409 {object} swaggerAPIErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/register [post]
func registerDoc() {}

// registerByPhoneDoc godoc
// @Summary Register by phone
// @Tags auth
// @Accept json
// @Produce json
// @Param body body registerByPhoneRequest true "Register by phone payload"
// @Success 201 {object} authn.RegisterResult
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 409 {object} swaggerAPIErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/register/phone [post]
func registerByPhoneDoc() {}

// sendSMSCodeDoc godoc
// @Summary Send registration SMS code
// @Tags auth
// @Accept json
// @Produce json
// @Param body body sendSMSCodeRequest true "SMS request"
// @Success 200 {object} swaggerOKResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/sms/send-code [post]
func sendSMSCodeDoc() {}

// verifyEmailDoc godoc
// @Summary Verify email by code
// @Tags auth
// @Accept json
// @Produce json
// @Param body body verifyEmailRequest true "Verify email payload"
// @Success 200 {object} swaggerVerifiedResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/verify-email [post]
func verifyEmailDoc() {}

// loginDoc godoc
// @Summary Login
// @Tags auth
// @Accept json
// @Produce json
// @Param body body loginRequest true "Login payload"
// @Success 200 {object} authn.TokenPair
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 401 {object} swaggerAPIErrorResponse
// @Failure 403 {object} swaggerAPIErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/login [post]
func loginDoc() {}

// refreshDoc godoc
// @Summary Refresh token pair
// @Tags auth
// @Accept json
// @Produce json
// @Param body body refreshRequest true "Refresh token payload"
// @Success 200 {object} authn.TokenPair
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 401 {object} swaggerAPIErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/refresh [post]
func refreshDoc() {}

// logoutDoc godoc
// @Summary Logout by refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param body body refreshRequest true "Refresh token payload"
// @Success 200 {object} swaggerOKResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/logout [post]
func logoutDoc() {}

// forgotPasswordDoc godoc
// @Summary Request password reset
// @Tags auth
// @Accept json
// @Produce json
// @Param body body forgotPasswordRequest true "Forgot password payload"
// @Success 200 {object} swaggerOKResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/password/forgot [post]
func forgotPasswordDoc() {}

// resetPasswordDoc godoc
// @Summary Reset password
// @Tags auth
// @Accept json
// @Produce json
// @Param body body resetPasswordRequest true "Reset password payload"
// @Success 200 {object} swaggerOKResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/password/reset [post]
func resetPasswordDoc() {}

// changePasswordDoc godoc
// @Summary Change current password
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body changePasswordRequest true "Change password payload"
// @Success 200 {object} swaggerOKResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerAPIErrorResponse
// @Router /api/v1/auth/password/change [post]
func changePasswordDoc() {}

// meDoc godoc
// @Summary Get current principal
// @Tags user
// @Security BearerAuth
// @Produce json
// @Success 200 {object} identity.Principal
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Router /api/v1/me [get]
func meDoc() {}

// liteLLMConfigDoc godoc
// @Summary Get LiteLLM client config
// @Tags litellm
// @Produce json
// @Success 200 {object} swaggerLiteLLMConfigResponse
// @Router /api/v1/config/litellm [get]
func liteLLMConfigDoc() {}

// tenantMembersDoc godoc
// @Summary List tenant members
// @Tags tenant
// @Security BearerAuth
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {object} swaggerMemberListResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 403 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerSimpleErrorResponse
// @Router /api/v1/tenants/{tenant_id}/members [get]
func tenantMembersDoc() {}

// permissionCheckDoc godoc
// @Summary Check a policy tuple
// @Tags authz
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body checkPermissionRequest true "Permission check payload"
// @Success 200 {object} swaggerAllowedResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerSimpleErrorResponse
// @Router /api/v1/permissions/check [post]
func permissionCheckDoc() {}

// writeRelationshipsDoc godoc
// @Summary Write policy relationships
// @Tags authz
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body writeRelationshipRequest true "Relationship payload"
// @Success 200 {object} swaggerWrittenResponse
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 403 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerSimpleErrorResponse
// @Router /api/v1/policies/relationships [post]
func writeRelationshipsDoc() {}

// auditEventsDoc godoc
// @Summary Query audit events
// @Tags audit
// @Security BearerAuth
// @Produce json
// @Param actor query string false "Actor filter"
// @Param action query string false "Action filter"
// @Param resource query string false "Resource filter"
// @Success 200 {object} swaggerAuditListResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 500 {object} swaggerSimpleErrorResponse
// @Router /api/v1/audit/events [get]
func auditEventsDoc() {}

// liteLLMMyCreditDoc godoc
// @Summary Get my LiteLLM credit snapshot
// @Tags litellm
// @Security BearerAuth
// @Produce json
// @Success 200 {object} litellmcredit.CreditSnapshot
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 503 {object} swaggerSimpleErrorResponse
// @Router /api/v1/litellm/me/credit [get]
func liteLLMMyCreditDoc() {}

// liteLLMMyCallsDoc godoc
// @Summary List my recent LiteLLM calls
// @Tags litellm
// @Security BearerAuth
// @Produce json
// @Param limit query int false "Max items (default 20)"
// @Success 200 {object} swaggerLiteLLMCallListResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 503 {object} swaggerSimpleErrorResponse
// @Router /api/v1/litellm/me/calls [get]
func liteLLMMyCallsDoc() {}

// liteLLMMyModelsDoc godoc
// @Summary List available LiteLLM models
// @Tags litellm
// @Security BearerAuth
// @Produce json
// @Success 200 {object} swaggerLiteLLMModelListResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 502 {object} swaggerAPIErrorResponse
// @Failure 503 {object} swaggerAPIErrorResponse
// @Router /api/v1/litellm/me/models [get]
func liteLLMMyModelsDoc() {}

// liteLLMCreditGetDoc godoc
// @Summary Get user credit snapshot (admin)
// @Tags litellm-admin
// @Security BearerAuth
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} litellmcredit.CreditSnapshot
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 403 {object} swaggerAPIErrorResponse
// @Failure 503 {object} swaggerSimpleErrorResponse
// @Router /api/v1/admin/litellm/credits/{tenant_id}/{user_id} [get]
func liteLLMCreditGetDoc() {}

// liteLLMCreditAdjustDoc godoc
// @Summary Adjust user credit (admin)
// @Tags litellm-admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body liteLLMCreditAdjustRequest true "Adjust payload"
// @Success 200 {object} litellmcredit.CreditSnapshot
// @Failure 400 {object} swaggerSimpleErrorResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 403 {object} swaggerAPIErrorResponse
// @Failure 503 {object} swaggerSimpleErrorResponse
// @Router /api/v1/admin/litellm/credits/adjust [post]
func liteLLMCreditAdjustDoc() {}

// liteLLMCreditEventsDoc godoc
// @Summary List credit events (admin)
// @Tags litellm-admin
// @Security BearerAuth
// @Produce json
// @Param limit query int false "Max items (default 50)"
// @Param offset query int false "Offset (default 0)"
// @Success 200 {object} swaggerLiteLLMEventListResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 403 {object} swaggerAPIErrorResponse
// @Failure 503 {object} swaggerSimpleErrorResponse
// @Router /api/v1/admin/litellm/events [get]
func liteLLMCreditEventsDoc() {}

// liteLLMRecentCallsDoc godoc
// @Summary List user recent calls (admin)
// @Tags litellm-admin
// @Security BearerAuth
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Param limit query int false "Max items (default 20)"
// @Success 200 {object} swaggerLiteLLMCallListResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Failure 403 {object} swaggerAPIErrorResponse
// @Failure 503 {object} swaggerSimpleErrorResponse
// @Router /api/v1/admin/litellm/calls/{tenant_id}/{user_id} [get]
func liteLLMRecentCallsDoc() {}

// liteLLMAccessDoc godoc
// @Summary Get LiteLLM admin access flags
// @Tags litellm-admin
// @Security BearerAuth
// @Produce json
// @Success 200 {object} swaggerLiteLLMAccessResponse
// @Failure 401 {object} swaggerSimpleErrorResponse
// @Router /api/v1/admin/litellm/access [get]
func liteLLMAccessDoc() {}
