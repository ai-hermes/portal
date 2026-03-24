package models

import "time"

type TenantScopedPrincipal struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role,omitempty"`
}

type ResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type PolicyTuple struct {
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type AuditEvent struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Result    string    `json:"result"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	TraceID   string    `json:"trace_id"`
	TenantID  string    `json:"tenant_id"`
	At        time.Time `json:"at"`
}

type RoleBinding struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Role     string `json:"role"`
}
