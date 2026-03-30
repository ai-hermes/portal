package api

import (
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/litellmcredit"
	"github.com/warjiang/portal/internal/models"
)

type errorMessageResponse struct {
	Error string `json:"error"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiErrorResponse struct {
	Error apiErrorBody `json:"error"`
}

type statusResponse struct {
	Status string `json:"status"`
}

type okResponse struct {
	OK bool `json:"ok"`
}

type verifiedResponse struct {
	Verified bool `json:"verified"`
}

type allowedResponse struct {
	Allowed bool `json:"allowed"`
}

type writtenResponse struct {
	Written int `json:"written"`
}

type tenantMembersResponse struct {
	Items []identity.Principal `json:"items"`
}

type auditEventsResponse struct {
	Items []models.AuditEvent `json:"items"`
}

type liteLLMEventsResponse struct {
	Items  []litellmcredit.CreditEvent `json:"items"`
	Limit  int                         `json:"limit"`
	Offset int                         `json:"offset"`
}

type liteLLMRecentCallsResponse struct {
	Items []litellmcredit.RecentCall `json:"items"`
	Limit int                        `json:"limit"`
}

type liteLLMAccessResponse struct {
	CanManage        bool `json:"can_manage"`
	ServiceAvailable bool `json:"service_available"`
}
