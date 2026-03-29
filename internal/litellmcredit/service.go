package litellmcredit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/litellm"
	"gorm.io/gorm"
)

type APIError struct {
	Code    string
	Message string
	Status  int
}

func (e *APIError) Error() string {
	return e.Message
}

func apiError(status int, code, message string) error {
	return &APIError{Status: status, Code: code, Message: message}
}

func AsAPIError(err error) (*APIError, bool) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

type Service struct {
	db             *gorm.DB
	client         *litellm.Client
	platformAdmins map[string]struct{}
	defaultQuota   float64
}

type Config struct {
	PlatformAdminEmails []string
	DefaultUserQuota    float64
}

func ParsePlatformAdminEmails(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		email := strings.ToLower(strings.TrimSpace(part))
		if email == "" {
			continue
		}
		if _, ok := seen[email]; ok {
			continue
		}
		seen[email] = struct{}{}
		out = append(out, email)
	}
	return out
}

func NewService(db *gorm.DB, client *litellm.Client, cfg Config) (*Service, error) {
	if db == nil {
		return nil, errors.New("db is required")
	}
	if client == nil {
		return nil, errors.New("litellm client is required")
	}
	admins := make(map[string]struct{}, len(cfg.PlatformAdminEmails))
	for _, email := range cfg.PlatformAdminEmails {
		norm := strings.ToLower(strings.TrimSpace(email))
		if norm == "" {
			continue
		}
		admins[norm] = struct{}{}
	}
	defaultQuota := cfg.DefaultUserQuota
	if math.IsNaN(defaultQuota) || math.IsInf(defaultQuota, 0) || defaultQuota <= 0 {
		defaultQuota = 10
	}
	return &Service{
		db:             db,
		client:         client,
		platformAdmins: admins,
		defaultQuota:   defaultQuota,
	}, nil
}

func (s *Service) IsPlatformAdmin(principal identity.Principal) bool {
	_, ok := s.platformAdmins[strings.ToLower(strings.TrimSpace(principal.Email))]
	return ok
}

type CreditSnapshot struct {
	TenantID        string    `json:"tenant_id"`
	UserID          string    `json:"user_id"`
	BudgetTotal     float64   `json:"budget_total"`
	SpendUsed       float64   `json:"spend_used"`
	BudgetRemaining float64   `json:"budget_remaining"`
	Unit            string    `json:"unit"`
	LastSyncedAt    time.Time `json:"last_synced_at"`
}

type AdjustInput struct {
	TenantID string
	UserID   string
	Mode     string
	Amount   float64
	Reason   string
}

type CreditEvent struct {
	ID           int64     `json:"id"`
	TenantID     string    `json:"tenant_id"`
	UserID       string    `json:"user_id"`
	ActorUserID  string    `json:"actor_user_id"`
	ActorEmail   string    `json:"actor_email"`
	Mode         string    `json:"mode"`
	Amount       float64   `json:"amount"`
	BeforeBudget float64   `json:"before_budget"`
	AfterBudget  float64   `json:"after_budget"`
	Result       string    `json:"result"`
	Reason       string    `json:"reason"`
	ErrorMessage string    `json:"error_message,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *Service) EnsureUserProvisioned(ctx context.Context, tenantID, userID string) error {
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	if tenantID == "" || userID == "" {
		return apiError(400, "invalid_request", "tenant_id and user_id are required")
	}
	email, err := s.ensureTenantUser(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	key, created, err := s.ensureUserKey(ctx, tenantID, userID, email)
	if err != nil {
		s.recordEvent(ctx, creditEventInput{
			actor:        systemActor(),
			tenantID:     tenantID,
			userID:       userID,
			mode:         "auto_provision",
			amount:       s.defaultQuota,
			beforeBudget: 0,
			afterBudget:  0,
			reason:       "auto_provision",
			result:       "fail",
			errorMessage: err.Error(),
		})
		return err
	}
	result := "skip_existing"
	if created {
		result = "success"
	}
	s.recordEvent(ctx, creditEventInput{
		actor:        systemActor(),
		tenantID:     tenantID,
		userID:       userID,
		mode:         "auto_provision",
		amount:       s.defaultQuota,
		beforeBudget: 0,
		afterBudget:  key.LastBudgetTotal,
		reason:       "auto_provision",
		result:       result,
	})
	return nil
}

func (s *Service) GetUserCredit(ctx context.Context, actor identity.Principal, tenantID, userID string) (CreditSnapshot, error) {
	if !s.IsPlatformAdmin(actor) {
		return CreditSnapshot{}, apiError(403, "insufficient_role", "platform admin role required")
	}
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	if tenantID == "" || userID == "" {
		return CreditSnapshot{}, apiError(400, "invalid_request", "tenant_id and user_id are required")
	}
	email, err := s.ensureTenantUser(ctx, tenantID, userID)
	if err != nil {
		return CreditSnapshot{}, err
	}

	key, _, err := s.ensureUserKey(ctx, tenantID, userID, email)
	if err != nil {
		return CreditSnapshot{}, err
	}
	record, err := s.client.GetKeyInfo(ctx, key.APIKey)
	if err != nil {
		return CreditSnapshot{}, apiError(502, "litellm_error", err.Error())
	}
	key.LastBudgetTotal = record.MaxBudget
	key.LastSpendUsed = record.Spend
	key.KeyAlias = firstNonEmpty(record.KeyAlias, key.KeyAlias)
	now := time.Now().UTC()
	key.LastSyncedAt = &now
	key.UpdatedAt = now
	if err := s.db.WithContext(ctx).Model(&litellmUserKeyModel{}).Where("id = ?", key.ID).Updates(map[string]any{
		"key_alias":         key.KeyAlias,
		"last_budget_total": key.LastBudgetTotal,
		"last_spend_used":   key.LastSpendUsed,
		"last_synced_at":    key.LastSyncedAt,
		"updated_at":        key.UpdatedAt,
	}).Error; err != nil {
		return CreditSnapshot{}, err
	}
	return toSnapshot(key), nil
}

func (s *Service) AdjustUserCredit(ctx context.Context, actor identity.Principal, in AdjustInput) (CreditSnapshot, error) {
	if !s.IsPlatformAdmin(actor) {
		return CreditSnapshot{}, apiError(403, "insufficient_role", "platform admin role required")
	}
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.UserID = strings.TrimSpace(in.UserID)
	in.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
	in.Reason = strings.TrimSpace(in.Reason)
	if in.TenantID == "" || in.UserID == "" {
		return CreditSnapshot{}, apiError(400, "invalid_request", "tenant_id and user_id are required")
	}
	if in.Mode != "set" && in.Mode != "delta" {
		return CreditSnapshot{}, apiError(400, "invalid_mode", "mode must be set or delta")
	}
	if in.Reason == "" {
		return CreditSnapshot{}, apiError(400, "invalid_reason", "reason is required")
	}
	if math.IsNaN(in.Amount) || math.IsInf(in.Amount, 0) {
		return CreditSnapshot{}, apiError(400, "invalid_amount", "amount must be a finite number")
	}

	email, err := s.ensureTenantUser(ctx, in.TenantID, in.UserID)
	if err != nil {
		return CreditSnapshot{}, err
	}
	key, _, err := s.ensureUserKey(ctx, in.TenantID, in.UserID, email)
	if err != nil {
		return CreditSnapshot{}, err
	}

	before, err := s.client.GetKeyInfo(ctx, key.APIKey)
	if err != nil {
		s.recordEvent(ctx, creditEventInput{actor: actor, tenantID: in.TenantID, userID: in.UserID, mode: in.Mode, amount: in.Amount, beforeBudget: key.LastBudgetTotal, afterBudget: key.LastBudgetTotal, reason: in.Reason, result: "fail", errorMessage: err.Error()})
		return CreditSnapshot{}, apiError(502, "litellm_error", err.Error())
	}

	targetBudget := in.Amount
	if in.Mode == "delta" {
		targetBudget = before.MaxBudget + in.Amount
	}
	if targetBudget < 0 {
		s.recordEvent(ctx, creditEventInput{actor: actor, tenantID: in.TenantID, userID: in.UserID, mode: in.Mode, amount: in.Amount, beforeBudget: before.MaxBudget, afterBudget: before.MaxBudget, reason: in.Reason, result: "deny", errorMessage: "target budget cannot be negative"})
		return CreditSnapshot{}, apiError(400, "invalid_amount", "target budget cannot be negative")
	}

	updated, err := s.client.UpdateKeyBudget(ctx, key.APIKey, targetBudget)
	if err != nil {
		s.recordEvent(ctx, creditEventInput{actor: actor, tenantID: in.TenantID, userID: in.UserID, mode: in.Mode, amount: in.Amount, beforeBudget: before.MaxBudget, afterBudget: before.MaxBudget, reason: in.Reason, result: "fail", errorMessage: err.Error()})
		return CreditSnapshot{}, apiError(502, "litellm_error", err.Error())
	}
	finalBudget := updated.MaxBudget
	if finalBudget == 0 && targetBudget > 0 {
		finalBudget = targetBudget
	}
	finalSpend := updated.Spend
	if latest, infoErr := s.client.GetKeyInfo(ctx, key.APIKey); infoErr == nil {
		finalBudget = latest.MaxBudget
		finalSpend = latest.Spend
		updated.KeyAlias = firstNonEmpty(latest.KeyAlias, updated.KeyAlias)
	}

	now := time.Now().UTC()
	key.KeyAlias = firstNonEmpty(updated.KeyAlias, key.KeyAlias)
	key.LastBudgetTotal = finalBudget
	key.LastSpendUsed = finalSpend
	key.LastSyncedAt = &now
	key.UpdatedAt = now
	if err := s.db.WithContext(ctx).Model(&litellmUserKeyModel{}).Where("id = ?", key.ID).Updates(map[string]any{
		"key_alias":         key.KeyAlias,
		"last_budget_total": key.LastBudgetTotal,
		"last_spend_used":   key.LastSpendUsed,
		"last_synced_at":    key.LastSyncedAt,
		"updated_at":        key.UpdatedAt,
	}).Error; err != nil {
		return CreditSnapshot{}, err
	}

	s.recordEvent(ctx, creditEventInput{actor: actor, tenantID: in.TenantID, userID: in.UserID, mode: in.Mode, amount: in.Amount, beforeBudget: before.MaxBudget, afterBudget: finalBudget, reason: in.Reason, result: "success"})
	return toSnapshot(key), nil
}

func (s *Service) ListEvents(ctx context.Context, actor identity.Principal, limit, offset int) ([]CreditEvent, error) {
	if !s.IsPlatformAdmin(actor) {
		return nil, apiError(403, "insufficient_role", "platform admin role required")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	var rows []litellmCreditEventModel
	err := s.db.WithContext(ctx).
		Model(&litellmCreditEventModel{}).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	items := make([]CreditEvent, 0, len(rows))
	for _, row := range rows {
		items = append(items, CreditEvent{
			ID:           row.ID,
			TenantID:     row.TenantID,
			UserID:       row.UserID,
			ActorUserID:  row.ActorUserID,
			ActorEmail:   row.ActorEmail,
			Mode:         row.Mode,
			Amount:       row.Amount,
			BeforeBudget: row.BeforeBudget,
			AfterBudget:  row.AfterBudget,
			Result:       row.Result,
			Reason:       row.Reason,
			ErrorMessage: row.ErrorMessage,
			CreatedAt:    row.CreatedAt,
		})
	}
	return items, nil
}

type litellmUserKeyModel struct {
	ID              string     `gorm:"column:id;primaryKey"`
	TenantID        string     `gorm:"column:tenant_id"`
	UserID          string     `gorm:"column:user_id"`
	APIKey          string     `gorm:"column:api_key"`
	KeyAlias        string     `gorm:"column:key_alias"`
	LastBudgetTotal float64    `gorm:"column:last_budget_total"`
	LastSpendUsed   float64    `gorm:"column:last_spend_used"`
	LastSyncedAt    *time.Time `gorm:"column:last_synced_at"`
	CreatedAt       time.Time  `gorm:"column:created_at"`
	UpdatedAt       time.Time  `gorm:"column:updated_at"`
}

func (litellmUserKeyModel) TableName() string { return "litellm_user_keys" }

type litellmCreditEventModel struct {
	ID           int64     `gorm:"column:id;primaryKey"`
	TenantID     string    `gorm:"column:tenant_id"`
	UserID       string    `gorm:"column:user_id"`
	ActorUserID  string    `gorm:"column:actor_user_id"`
	ActorEmail   string    `gorm:"column:actor_email"`
	Mode         string    `gorm:"column:mode"`
	Amount       float64   `gorm:"column:amount"`
	BeforeBudget float64   `gorm:"column:before_budget"`
	AfterBudget  float64   `gorm:"column:after_budget"`
	Result       string    `gorm:"column:result"`
	Reason       string    `gorm:"column:reason"`
	ErrorMessage string    `gorm:"column:error_message"`
	CreatedAt    time.Time `gorm:"column:created_at"`
}

func (litellmCreditEventModel) TableName() string { return "litellm_credit_events" }

func (s *Service) ensureTenantUser(ctx context.Context, tenantID, userID string) (string, error) {
	var row struct {
		Email *string `gorm:"column:email"`
	}
	err := s.db.WithContext(ctx).
		Table("tenant_members").
		Select("users.email").
		Joins("JOIN users ON users.id = tenant_members.user_id").
		Where("tenant_members.tenant_id = ? AND tenant_members.user_id = ?", tenantID, userID).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", apiError(404, "user_not_found", "user not found in tenant")
		}
		return "", err
	}
	if row.Email == nil {
		return "", nil
	}
	return *row.Email, nil
}

func (s *Service) ensureUserKey(ctx context.Context, tenantID, userID, email string) (litellmUserKeyModel, bool, error) {
	var model litellmUserKeyModel
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Take(&model).Error
	if err == nil {
		return model, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return litellmUserKeyModel{}, false, err
	}

	now := time.Now().UTC()
	alias := fmt.Sprintf("%s:%s", tenantID, userID)
	litellmUserID := buildLiteLLMUserID(tenantID, userID)
	if err := s.client.EnsureUser(ctx, litellm.EnsureUserInput{
		UserID: litellmUserID,
		Metadata: map[string]any{
			"tenant_id":    tenantID,
			"portal_user":  userID,
			"portal_email": email,
		},
	}); err != nil {
		return litellmUserKeyModel{}, false, apiError(502, "litellm_error", err.Error())
	}
	generated, err := s.client.GenerateKey(ctx, litellm.GenerateKeyInput{
		KeyAlias:  alias,
		MaxBudget: s.defaultQuota,
		UserID:    litellmUserID,
		Metadata: map[string]any{
			"tenant_id": tenantID,
			"user_id":   userID,
			"email":     email,
		},
	})
	if err != nil {
		return litellmUserKeyModel{}, false, apiError(502, "litellm_error", err.Error())
	}
	if s.defaultQuota > 0 && generated.MaxBudget < s.defaultQuota {
		updated, updateErr := s.client.UpdateKeyBudget(ctx, generated.APIKey, s.defaultQuota)
		if updateErr != nil {
			return litellmUserKeyModel{}, false, apiError(502, "litellm_error", updateErr.Error())
		}
		generated.MaxBudget = updated.MaxBudget
		generated.Spend = updated.Spend
		generated.KeyAlias = firstNonEmpty(updated.KeyAlias, generated.KeyAlias)
	}
	if generated.MaxBudget <= 0 {
		generated.MaxBudget = s.defaultQuota
	}
	model = litellmUserKeyModel{
		ID:              "lk_" + randomID(12),
		TenantID:        tenantID,
		UserID:          userID,
		APIKey:          generated.APIKey,
		KeyAlias:        firstNonEmpty(generated.KeyAlias, alias),
		LastBudgetTotal: generated.MaxBudget,
		LastSpendUsed:   generated.Spend,
		LastSyncedAt:    &now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := s.db.WithContext(ctx).Create(&model).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "SQLSTATE 23505") {
			var existing litellmUserKeyModel
			if findErr := s.db.WithContext(ctx).Where("tenant_id = ? AND user_id = ?", tenantID, userID).Take(&existing).Error; findErr == nil {
				return existing, false, nil
			}
		}
		return litellmUserKeyModel{}, false, err
	}
	return model, true, nil
}

type creditEventInput struct {
	actor        identity.Principal
	tenantID     string
	userID       string
	mode         string
	amount       float64
	beforeBudget float64
	afterBudget  float64
	reason       string
	result       string
	errorMessage string
}

func (s *Service) recordEvent(ctx context.Context, in creditEventInput) {
	now := time.Now().UTC()
	_ = s.db.WithContext(ctx).Create(&litellmCreditEventModel{
		TenantID:     in.tenantID,
		UserID:       in.userID,
		ActorUserID:  in.actor.UserID,
		ActorEmail:   in.actor.Email,
		Mode:         in.mode,
		Amount:       in.amount,
		BeforeBudget: in.beforeBudget,
		AfterBudget:  in.afterBudget,
		Result:       in.result,
		Reason:       in.reason,
		ErrorMessage: in.errorMessage,
		CreatedAt:    now,
	}).Error
}

func toSnapshot(row litellmUserKeyModel) CreditSnapshot {
	lastSyncedAt := row.UpdatedAt
	if row.LastSyncedAt != nil {
		lastSyncedAt = *row.LastSyncedAt
	}
	remaining := row.LastBudgetTotal - row.LastSpendUsed
	if remaining < 0 {
		remaining = 0
	}
	return CreditSnapshot{
		TenantID:        row.TenantID,
		UserID:          row.UserID,
		BudgetTotal:     row.LastBudgetTotal,
		SpendUsed:       row.LastSpendUsed,
		BudgetRemaining: remaining,
		Unit:            "litellm_spend",
		LastSyncedAt:    lastSyncedAt,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func randomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func systemActor() identity.Principal {
	return identity.Principal{
		UserID: "system",
		Email:  "system@internal",
	}
}

func buildLiteLLMUserID(tenantID, userID string) string {
	return fmt.Sprintf("%s:%s", strings.TrimSpace(tenantID), strings.TrimSpace(userID))
}
