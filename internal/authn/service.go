package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/models"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	passwordHasLetter = regexp.MustCompile(`[A-Za-z]`)
	passwordHasDigit  = regexp.MustCompile(`[0-9]`)
	cnPhonePattern    = regexp.MustCompile(`^1[0-9]{10}$`)
)

type Config struct {
	JWTSigningKey       string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	EmailCodeTTL        time.Duration
	SMSCodeTTL          time.Duration
	SMSRateWindow       time.Duration
	SMSResendInterval   time.Duration
	SMSMaxPerPhone      int
	SMSMaxPerIP         int
	PasswordResetTTL    time.Duration
	BcryptCost          int
	DefaultTenantPrefix string
}

func (c Config) withDefaults() Config {
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = 15 * time.Minute
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if c.EmailCodeTTL <= 0 {
		c.EmailCodeTTL = 10 * time.Minute
	}
	if c.SMSCodeTTL <= 0 {
		c.SMSCodeTTL = 10 * time.Minute
	}
	if c.SMSRateWindow <= 0 {
		c.SMSRateWindow = 10 * time.Minute
	}
	if c.SMSResendInterval <= 0 {
		c.SMSResendInterval = 60 * time.Second
	}
	if c.SMSMaxPerPhone <= 0 {
		c.SMSMaxPerPhone = 5
	}
	if c.SMSMaxPerIP <= 0 {
		c.SMSMaxPerIP = 20
	}
	if c.PasswordResetTTL <= 0 {
		c.PasswordResetTTL = 15 * time.Minute
	}
	if c.BcryptCost <= 0 {
		c.BcryptCost = bcrypt.DefaultCost
	}
	if c.DefaultTenantPrefix == "" {
		c.DefaultTenantPrefix = "tenant"
	}
	return c
}

type EmailProvider interface {
	SendVerificationCode(ctx context.Context, email, code string) error
	SendPasswordResetToken(ctx context.Context, email, token string) error
}

type SMSProvider interface {
	SendRegisterCode(ctx context.Context, phone, code string) error
}

type UserProvisioner interface {
	EnsureUserProvisioned(ctx context.Context, tenantID, userID string) error
}

type Service struct {
	db          *gorm.DB
	cfg         Config
	email       EmailProvider
	sms         SMSProvider
	audit       *audit.Service
	provisioner UserProvisioner
	logger      *zap.Logger
	authLog     *zap.Logger
}

func NewService(db *gorm.DB, cfg Config, email EmailProvider, sms SMSProvider, auditSvc *audit.Service, provisioner UserProvisioner, logger *zap.Logger) (*Service, error) {
	cfg = cfg.withDefaults()
	if strings.TrimSpace(cfg.JWTSigningKey) == "" {
		return nil, errors.New("JWT_SIGNING_KEY is required")
	}
	if email == nil {
		return nil, errors.New("email provider is required")
	}
	if sms == nil {
		return nil, errors.New("sms provider is required")
	}
	if db == nil {
		return nil, errors.New("db is required")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{
		db:          db,
		cfg:         cfg,
		email:       email,
		sms:         sms,
		audit:       auditSvc,
		provisioner: provisioner,
		logger:      logger,
		authLog:     logger.Named("authn"),
	}, nil
}

type userModel struct {
	ID              string     `gorm:"column:id;primaryKey"`
	Email           *string    `gorm:"column:email"`
	Phone           *string    `gorm:"column:phone"`
	PasswordHash    string     `gorm:"column:password_hash"`
	DisplayName     string     `gorm:"column:display_name"`
	EmailVerifiedAt *time.Time `gorm:"column:email_verified_at"`
	PhoneVerifiedAt *time.Time `gorm:"column:phone_verified_at"`
	Status          string     `gorm:"column:status"`
	CreatedAt       time.Time  `gorm:"column:created_at"`
	UpdatedAt       time.Time  `gorm:"column:updated_at"`
}

func (userModel) TableName() string { return "users" }

type tenantModel struct {
	ID        string    `gorm:"column:id;primaryKey"`
	Name      string    `gorm:"column:name"`
	CreatedBy string    `gorm:"column:created_by"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (tenantModel) TableName() string { return "tenants" }

type tenantMemberModel struct {
	TenantID  string    `gorm:"column:tenant_id;primaryKey"`
	UserID    string    `gorm:"column:user_id;primaryKey"`
	Role      string    `gorm:"column:role"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (tenantMemberModel) TableName() string { return "tenant_members" }

type refreshTokenModel struct {
	ID        string     `gorm:"column:id;primaryKey"`
	UserID    string     `gorm:"column:user_id"`
	TenantID  string     `gorm:"column:tenant_id"`
	TokenHash string     `gorm:"column:token_hash"`
	IssuedAt  time.Time  `gorm:"column:issued_at"`
	ExpiresAt time.Time  `gorm:"column:expires_at"`
	RevokedAt *time.Time `gorm:"column:revoked_at"`
	UserAgent string     `gorm:"column:user_agent"`
	IP        string     `gorm:"column:ip"`
}

func (refreshTokenModel) TableName() string { return "refresh_tokens" }

type emailVerificationModel struct {
	ID        string     `gorm:"column:id;primaryKey"`
	UserID    string     `gorm:"column:user_id"`
	CodeHash  string     `gorm:"column:code_hash"`
	ExpiresAt time.Time  `gorm:"column:expires_at"`
	UsedAt    *time.Time `gorm:"column:used_at"`
	CreatedAt time.Time  `gorm:"column:created_at"`
}

func (emailVerificationModel) TableName() string { return "email_verifications" }

type smsVerificationModel struct {
	ID        string     `gorm:"column:id;primaryKey"`
	Phone     string     `gorm:"column:phone"`
	Purpose   string     `gorm:"column:purpose"`
	CodeHash  string     `gorm:"column:code_hash"`
	ExpiresAt time.Time  `gorm:"column:expires_at"`
	UsedAt    *time.Time `gorm:"column:used_at"`
	CreatedAt time.Time  `gorm:"column:created_at"`
	RequestIP string     `gorm:"column:request_ip"`
}

func (smsVerificationModel) TableName() string { return "sms_verifications" }

type passwordResetModel struct {
	ID        string     `gorm:"column:id;primaryKey"`
	UserID    string     `gorm:"column:user_id"`
	TokenHash string     `gorm:"column:token_hash"`
	ExpiresAt time.Time  `gorm:"column:expires_at"`
	UsedAt    *time.Time `gorm:"column:used_at"`
	CreatedAt time.Time  `gorm:"column:created_at"`
}

func (passwordResetModel) TableName() string { return "password_resets" }

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

type RegisterInput struct {
	Email       string
	Password    string
	DisplayName string
}

type RegisterResult struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
}

type SendSMSCodeInput struct {
	Phone   string
	Purpose string
}

type RegisterPhoneInput struct {
	Phone       string
	Code        string
	Password    string
	DisplayName string
}

func (s *Service) Register(ctx context.Context, in RegisterInput, remoteAddr, userAgent string) (RegisterResult, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	s.authLog.Info("register attempt", zap.String("email", email), zap.String("remote_addr", remoteAddr), zap.String("user_agent", userAgent))
	if err := validateEmail(email); err != nil {
		s.authLog.Warn("register invalid email", zap.String("email", email), zap.Error(err))
		return RegisterResult{}, apiError(400, "invalid_email", err.Error())
	}
	if err := validatePassword(in.Password); err != nil {
		s.authLog.Warn("register weak password", zap.String("email", email), zap.Error(err))
		return RegisterResult{}, apiError(400, "weak_password", err.Error())
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), s.cfg.BcryptCost)
	if err != nil {
		s.authLog.Error("register hash password failed", zap.String("email", email), zap.Error(err))
		return RegisterResult{}, err
	}

	userID := "u_" + randomID(12)
	tenantID := fmt.Sprintf("%s-%s", s.cfg.DefaultTenantPrefix, randomID(8))
	now := time.Now().UTC()
	code := randomDigits(6)
	codeHash := hashToken(code)

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&userModel{
			ID:           userID,
			Email:        &email,
			PasswordHash: string(hash),
			DisplayName:  strings.TrimSpace(in.DisplayName),
			Status:       "active",
			CreatedAt:    now,
			UpdatedAt:    now,
		}).Error; err != nil {
			if isUniqueViolation(err) {
				return apiError(409, "email_already_exists", "email already exists")
			}
			return err
		}

		if err := tx.Create(&tenantModel{
			ID:        tenantID,
			Name:      "Personal Workspace",
			CreatedBy: userID,
			CreatedAt: now,
		}).Error; err != nil {
			return err
		}

		if err := tx.Create(&tenantMemberModel{
			TenantID:  tenantID,
			UserID:    userID,
			Role:      "tenant_admin",
			CreatedAt: now,
		}).Error; err != nil {
			return err
		}

		return tx.Create(&emailVerificationModel{
			ID:        "ev_" + randomID(12),
			UserID:    userID,
			CodeHash:  codeHash,
			ExpiresAt: now.Add(s.cfg.EmailCodeTTL),
			CreatedAt: now,
		}).Error
	})
	if err != nil {
		s.authLog.Warn("register transaction failed", zap.String("email", email), zap.Error(err))
		return RegisterResult{}, err
	}

	if err := s.email.SendVerificationCode(ctx, email, code); err != nil {
		s.authLog.Warn("send email verification code failed", zap.String("email", email), zap.String("code", code), zap.Error(err))
	} else {
		s.authLog.Info("send email verification code success", zap.String("email", email), zap.String("code", code))
	}

	s.recordAudit(ctx, models.AuditEvent{
		Actor:     userID,
		Action:    "auth_register",
		Resource:  "user",
		Result:    "success",
		TenantID:  tenantID,
		IP:        remoteAddr,
		UserAgent: userAgent,
	})
	s.ensureLiteLLMProvisioned(ctx, userID, tenantID, remoteAddr, userAgent, "register")
	s.authLog.Info("register success", zap.String("email", email), zap.String("user_id", userID), zap.String("tenant_id", tenantID))

	return RegisterResult{UserID: userID, TenantID: tenantID}, nil
}

func (s *Service) SendSMSCode(ctx context.Context, in SendSMSCodeInput, remoteAddr string) error {
	phone := strings.TrimSpace(in.Phone)
	s.authLog.Info("send sms code attempt", zap.String("phone", phone), zap.String("purpose", strings.TrimSpace(in.Purpose)), zap.String("remote_addr", remoteAddr))
	if err := validateCNPhone(phone); err != nil {
		s.authLog.Warn("send sms code invalid phone", zap.String("phone", phone), zap.Error(err))
		return apiError(400, "invalid_phone", err.Error())
	}
	in.Purpose = strings.TrimSpace(in.Purpose)
	if in.Purpose == "" {
		in.Purpose = "register"
	}
	if in.Purpose != "register" {
		s.authLog.Warn("send sms code invalid purpose", zap.String("phone", phone), zap.String("purpose", in.Purpose))
		return apiError(400, "invalid_purpose", "unsupported sms purpose")
	}

	if remoteAddr == "" {
		remoteAddr = "unknown"
	}

	threshold := time.Now().UTC().Add(-s.cfg.SMSRateWindow)

	var recentByPhone int64
	err := s.db.WithContext(ctx).
		Model(&smsVerificationModel{}).
		Where("phone = ? AND purpose = ? AND created_at > ?", phone, in.Purpose, threshold).
		Count(&recentByPhone).Error
	if err != nil {
		s.authLog.Error("count sms requests by phone failed", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.Error(err))
		return err
	}
	if recentByPhone >= int64(s.cfg.SMSMaxPerPhone) {
		s.authLog.Warn("send sms code denied by phone rate limit", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.Int64("recent_count", recentByPhone), zap.Int("max_per_phone", s.cfg.SMSMaxPerPhone))
		return apiError(429, "too_many_requests", "too many requests for this phone")
	}

	var recentByIP int64
	err = s.db.WithContext(ctx).
		Model(&smsVerificationModel{}).
		Where("request_ip = ? AND purpose = ? AND created_at > ?", remoteAddr, in.Purpose, threshold).
		Count(&recentByIP).Error
	if err != nil {
		s.authLog.Error("count sms requests by ip failed", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.String("request_ip", remoteAddr), zap.Error(err))
		return err
	}
	if recentByIP >= int64(s.cfg.SMSMaxPerIP) {
		s.authLog.Warn("send sms code denied by ip rate limit", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.String("request_ip", remoteAddr), zap.Int64("recent_count", recentByIP), zap.Int("max_per_ip", s.cfg.SMSMaxPerIP))
		return apiError(429, "too_many_requests", "too many requests from this IP")
	}

	var latest smsVerificationModel
	err = s.db.WithContext(ctx).
		Where("phone = ? AND purpose = ?", phone, in.Purpose).
		Order("created_at DESC").
		Take(&latest).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		s.authLog.Error("query latest sms verification failed", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.Error(err))
		return err
	}
	if err == nil && time.Since(latest.CreatedAt) < s.cfg.SMSResendInterval {
		s.authLog.Warn("send sms code denied by resend interval", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.Duration("resend_interval", s.cfg.SMSResendInterval))
		return apiError(429, "too_many_requests", "sms code requested too frequently")
	}

	code := randomDigits(6)
	verificationID := "sv_" + randomID(12)
	now := time.Now().UTC()
	err = s.db.WithContext(ctx).Create(&smsVerificationModel{
		ID:        verificationID,
		Phone:     phone,
		Purpose:   in.Purpose,
		CodeHash:  hashToken(code),
		ExpiresAt: now.Add(s.cfg.SMSCodeTTL),
		CreatedAt: now,
		RequestIP: remoteAddr,
	}).Error
	if err != nil {
		s.authLog.Error("create sms verification failed", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.Error(err))
		return err
	}

	if err := s.sms.SendRegisterCode(ctx, phone, code); err != nil {
		_ = s.db.WithContext(ctx).Delete(&smsVerificationModel{}, "id = ?", verificationID).Error
		s.authLog.Warn("send sms verification code failed", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.String("code", code), zap.Error(err))
		return apiError(500, "sms_send_failed", "failed to send sms verification code")
	}
	s.authLog.Info("send sms code success", zap.String("phone", phone), zap.String("purpose", in.Purpose), zap.String("code", code), zap.String("verification_id", verificationID))
	return nil
}

func (s *Service) RegisterByPhone(ctx context.Context, in RegisterPhoneInput, remoteAddr, userAgent string) (RegisterResult, error) {
	phone := strings.TrimSpace(in.Phone)
	s.authLog.Info("register by phone attempt", zap.String("phone", phone), zap.String("remote_addr", remoteAddr), zap.String("user_agent", userAgent))
	if err := validateCNPhone(phone); err != nil {
		s.authLog.Warn("register by phone invalid phone", zap.String("phone", phone), zap.Error(err))
		return RegisterResult{}, apiError(400, "invalid_phone", err.Error())
	}
	if strings.TrimSpace(in.Code) == "" {
		s.authLog.Warn("register by phone missing verification code", zap.String("phone", phone))
		return RegisterResult{}, apiError(400, "invalid_request", "code is required")
	}
	if err := validatePassword(in.Password); err != nil {
		s.authLog.Warn("register by phone weak password", zap.String("phone", phone), zap.Error(err))
		return RegisterResult{}, apiError(400, "weak_password", err.Error())
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), s.cfg.BcryptCost)
	if err != nil {
		s.authLog.Error("register by phone hash password failed", zap.String("phone", phone), zap.Error(err))
		return RegisterResult{}, err
	}

	userID := "u_" + randomID(12)
	tenantID := fmt.Sprintf("%s-%s", s.cfg.DefaultTenantPrefix, randomID(8))
	now := time.Now().UTC()

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&smsVerificationModel{}).
			Where("phone = ? AND purpose = ? AND code_hash = ? AND used_at IS NULL AND expires_at > ?", phone, "register", hashToken(strings.TrimSpace(in.Code)), now).
			Update("used_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return apiError(400, "invalid_verification_code", "invalid verification code")
		}

		if err := tx.Create(&userModel{
			ID:              userID,
			Phone:           &phone,
			PasswordHash:    string(hash),
			DisplayName:     strings.TrimSpace(in.DisplayName),
			PhoneVerifiedAt: &now,
			Status:          "active",
			CreatedAt:       now,
			UpdatedAt:       now,
		}).Error; err != nil {
			if isUniqueViolation(err) {
				return apiError(409, "phone_already_exists", "phone already exists")
			}
			return err
		}

		if err := tx.Create(&tenantModel{
			ID:        tenantID,
			Name:      "Personal Workspace",
			CreatedBy: userID,
			CreatedAt: now,
		}).Error; err != nil {
			return err
		}

		return tx.Create(&tenantMemberModel{
			TenantID:  tenantID,
			UserID:    userID,
			Role:      "tenant_admin",
			CreatedAt: now,
		}).Error
	})
	if err != nil {
		s.authLog.Warn("register by phone transaction failed", zap.String("phone", phone), zap.Error(err))
		return RegisterResult{}, err
	}

	s.recordAudit(ctx, models.AuditEvent{
		Actor:     userID,
		Action:    "auth_register_phone",
		Resource:  "user",
		Result:    "success",
		TenantID:  tenantID,
		IP:        remoteAddr,
		UserAgent: userAgent,
	})
	s.ensureLiteLLMProvisioned(ctx, userID, tenantID, remoteAddr, userAgent, "register_phone")
	s.authLog.Info("register by phone success", zap.String("phone", phone), zap.String("user_id", userID), zap.String("tenant_id", tenantID))

	return RegisterResult{UserID: userID, TenantID: tenantID}, nil
}

type VerifyEmailInput struct {
	Email string
	Code  string
}

func (s *Service) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	code := strings.TrimSpace(in.Code)
	if email == "" || code == "" {
		return apiError(400, "invalid_request", "email and code are required")
	}

	now := time.Now().UTC()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user userModel
		if err := tx.Select("id").Where("email = ?", email).Take(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return apiError(400, "invalid_verification_code", "invalid verification code")
			}
			return err
		}

		result := tx.Model(&emailVerificationModel{}).
			Where("user_id = ? AND code_hash = ? AND used_at IS NULL AND expires_at > ?", user.ID, hashToken(code), now).
			Update("used_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return apiError(400, "invalid_verification_code", "invalid verification code")
		}

		return tx.Model(&userModel{}).
			Where("id = ?", user.ID).
			Updates(map[string]any{"email_verified_at": now, "updated_at": now}).Error
	})
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Service) Login(ctx context.Context, account, password, remoteAddr, userAgent string) (TokenPair, error) {
	account = strings.TrimSpace(account)
	s.authLog.Info("login attempt", zap.String("account", account), zap.String("remote_addr", remoteAddr), zap.String("user_agent", userAgent))
	if account == "" || strings.TrimSpace(password) == "" {
		s.authLog.Warn("login invalid request", zap.String("account", account))
		return TokenPair{}, apiError(400, "invalid_request", "account and password are required")
	}

	lookupByPhone := cnPhonePattern.MatchString(account)
	lookupValue := strings.ToLower(account)
	if lookupByPhone {
		lookupValue = account
	}

	var row struct {
		UserID          string     `gorm:"column:user_id"`
		PasswordHash    string     `gorm:"column:password_hash"`
		EmailVerifiedAt *time.Time `gorm:"column:email_verified_at"`
		PhoneVerifiedAt *time.Time `gorm:"column:phone_verified_at"`
		TenantID        string     `gorm:"column:tenant_id"`
		Role            string     `gorm:"column:role"`
	}

	query := s.db.WithContext(ctx).
		Model(&userModel{}).
		Select("users.id AS user_id, users.password_hash, users.email_verified_at, users.phone_verified_at, tenant_members.tenant_id, tenant_members.role").
		Joins("JOIN tenant_members ON tenant_members.user_id = users.id").
		Order("tenant_members.created_at ASC")
	if lookupByPhone {
		query = query.Where("users.phone = ?", lookupValue)
	} else {
		query = query.Where("users.email = ?", lookupValue)
	}

	err := query.Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			s.authLog.Warn("login user not found", zap.String("account", account), zap.Bool("lookup_by_phone", lookupByPhone))
			return TokenPair{}, apiError(401, "invalid_credentials", "invalid account or password")
		}
		s.authLog.Error("login query failed", zap.String("account", account), zap.Bool("lookup_by_phone", lookupByPhone), zap.Error(err))
		return TokenPair{}, err
	}

	if bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte(password)) != nil {
		s.recordAudit(ctx, models.AuditEvent{Actor: row.UserID, Action: "auth_login", Resource: "session", Result: "deny", TenantID: row.TenantID, IP: remoteAddr, UserAgent: userAgent})
		s.authLog.Warn("login invalid credentials", zap.String("account", account), zap.String("user_id", row.UserID), zap.String("tenant_id", row.TenantID))
		return TokenPair{}, apiError(401, "invalid_credentials", "invalid account or password")
	}
	if lookupByPhone && row.PhoneVerifiedAt == nil {
		s.authLog.Warn("login blocked: phone not verified", zap.String("account", account), zap.String("user_id", row.UserID), zap.String("tenant_id", row.TenantID))
		return TokenPair{}, apiError(403, "phone_not_verified", "phone is not verified")
	}
	if !lookupByPhone && row.EmailVerifiedAt == nil {
		s.authLog.Warn("login blocked: email not verified", zap.String("account", account), zap.String("user_id", row.UserID), zap.String("tenant_id", row.TenantID))
		return TokenPair{}, apiError(403, "email_not_verified", "email is not verified")
	}

	pair, err := s.issueTokenPair(ctx, row.UserID, row.TenantID, row.Role, remoteAddr, userAgent)
	if err != nil {
		s.authLog.Error("login issue token pair failed", zap.String("account", account), zap.String("user_id", row.UserID), zap.String("tenant_id", row.TenantID), zap.Error(err))
		return TokenPair{}, err
	}

	s.recordAudit(ctx, models.AuditEvent{Actor: row.UserID, Action: "auth_login", Resource: "session", Result: "success", TenantID: row.TenantID, IP: remoteAddr, UserAgent: userAgent})
	s.ensureLiteLLMProvisioned(ctx, row.UserID, row.TenantID, remoteAddr, userAgent, "login")
	s.authLog.Info("login success", zap.String("account", account), zap.String("user_id", row.UserID), zap.String("tenant_id", row.TenantID))
	return pair, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken, remoteAddr, userAgent string) (TokenPair, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return TokenPair{}, apiError(400, "invalid_request", "refresh_token is required")
	}

	var pair TokenPair
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row struct {
			ID       string `gorm:"column:id"`
			UserID   string `gorm:"column:user_id"`
			TenantID string `gorm:"column:tenant_id"`
			Role     string `gorm:"column:role"`
		}
		now := time.Now().UTC()
		if err := tx.Model(&refreshTokenModel{}).
			Select("refresh_tokens.id, refresh_tokens.user_id, refresh_tokens.tenant_id, tenant_members.role").
			Joins("JOIN tenant_members ON tenant_members.user_id = refresh_tokens.user_id AND tenant_members.tenant_id = refresh_tokens.tenant_id").
			Where("refresh_tokens.token_hash = ? AND refresh_tokens.revoked_at IS NULL AND refresh_tokens.expires_at > ?", hashToken(refreshToken), now).
			Take(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return apiError(401, "invalid_refresh_token", "invalid refresh token")
			}
			return err
		}

		if err := tx.Model(&refreshTokenModel{}).
			Where("id = ?", row.ID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}

		accessToken, expiresAt, err := s.buildAccessToken(row.UserID, row.TenantID, row.Role)
		if err != nil {
			return err
		}
		newRefresh := randomToken(32)
		if err := tx.Create(&refreshTokenModel{
			ID:        "rt_" + randomID(12),
			UserID:    row.UserID,
			TenantID:  row.TenantID,
			TokenHash: hashToken(newRefresh),
			IssuedAt:  now,
			ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
			UserAgent: userAgent,
			IP:        remoteAddr,
		}).Error; err != nil {
			return err
		}

		pair = TokenPair{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
			RefreshToken: newRefresh,
		}
		return nil
	})
	if err != nil {
		return TokenPair{}, err
	}
	return pair, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	if strings.TrimSpace(refreshToken) == "" {
		return apiError(400, "invalid_request", "refresh_token is required")
	}
	now := time.Now().UTC()
	return s.db.WithContext(ctx).
		Model(&refreshTokenModel{}).
		Where("token_hash = ? AND revoked_at IS NULL", hashToken(refreshToken)).
		Update("revoked_at", now).Error
}

func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	if strings.TrimSpace(oldPassword) == "" || strings.TrimSpace(newPassword) == "" {
		return apiError(400, "invalid_request", "old_password and new_password are required")
	}
	if err := validatePassword(newPassword); err != nil {
		return apiError(400, "weak_password", err.Error())
	}

	var oldHashRow struct {
		PasswordHash string `gorm:"column:password_hash"`
	}
	if err := s.db.WithContext(ctx).Model(&userModel{}).Select("password_hash").Where("id = ?", userID).Take(&oldHashRow).Error; err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(oldHashRow.PasswordHash), []byte(oldPassword)) != nil {
		return apiError(401, "invalid_credentials", "old password is incorrect")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	err = s.db.WithContext(ctx).Model(&userModel{}).Where("id = ?", userID).
		Updates(map[string]any{"password_hash": string(newHash), "updated_at": now}).Error
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Model(&refreshTokenModel{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", now).Error
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		s.authLog.Warn("request password reset invalid request")
		return apiError(400, "invalid_request", "email is required")
	}
	var userID string
	var user userModel
	err := s.db.WithContext(ctx).Select("id").Where("email = ?", email).Take(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			s.authLog.Info("request password reset ignored, email not found", zap.String("email", email))
			return nil
		}
		s.authLog.Error("request password reset query failed", zap.String("email", email), zap.Error(err))
		return err
	}
	userID = user.ID

	token := randomToken(32)
	now := time.Now().UTC()
	err = s.db.WithContext(ctx).Create(&passwordResetModel{
		ID:        "pr_" + randomID(12),
		UserID:    userID,
		TokenHash: hashToken(token),
		ExpiresAt: now.Add(s.cfg.PasswordResetTTL),
		CreatedAt: now,
	}).Error
	if err != nil {
		s.authLog.Error("request password reset create token failed", zap.String("email", email), zap.String("user_id", userID), zap.Error(err))
		return err
	}
	if err := s.email.SendPasswordResetToken(ctx, email, token); err != nil {
		s.authLog.Warn("send reset token failed", zap.String("email", email), zap.String("token", token), zap.Error(err))
	} else {
		s.authLog.Info("send reset token success", zap.String("email", email), zap.String("token", token))
	}
	return nil
}

func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(newPassword) == "" {
		return apiError(400, "invalid_request", "token and new_password are required")
	}
	if err := validatePassword(newPassword); err != nil {
		return apiError(400, "weak_password", err.Error())
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		var reset passwordResetModel
		if err := tx.Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", hashToken(token), now).
			Order("created_at DESC").
			Take(&reset).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return apiError(400, "invalid_reset_token", "invalid reset token")
			}
			return err
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
		if err != nil {
			return err
		}
		if err := tx.Model(&userModel{}).
			Where("id = ?", reset.UserID).
			Updates(map[string]any{"password_hash": string(hash), "updated_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Model(&passwordResetModel{}).
			Where("token_hash = ? AND used_at IS NULL", hashToken(token)).
			Update("used_at", now).Error; err != nil {
			return err
		}
		return tx.Model(&refreshTokenModel{}).
			Where("user_id = ? AND revoked_at IS NULL", reset.UserID).
			Update("revoked_at", now).Error
	})
}

func (s *Service) AuthenticateAccessToken(ctx context.Context, token string) (identity.Principal, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.cfg.JWTSigningKey), nil
	})
	if err != nil || !parsed.Valid {
		return identity.Principal{}, apiError(401, "invalid_access_token", "invalid access token")
	}

	userID, _ := claims["sub"].(string)
	tenantID, _ := claims["tenant_id"].(string)
	role, _ := claims["role"].(string)
	if userID == "" || tenantID == "" {
		return identity.Principal{}, apiError(401, "invalid_access_token", "invalid access token")
	}

	var row struct {
		Email *string `gorm:"column:email"`
		Role  string  `gorm:"column:role"`
	}
	err = s.db.WithContext(ctx).
		Model(&userModel{}).
		Select("users.email, tenant_members.role").
		Joins("JOIN tenant_members ON tenant_members.user_id = users.id").
		Where("users.id = ? AND tenant_members.tenant_id = ?", userID, tenantID).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return identity.Principal{}, apiError(401, "invalid_access_token", "invalid access token")
		}
		return identity.Principal{}, err
	}
	email := ""
	if row.Email != nil {
		email = *row.Email
	}
	if role == "" {
		role = row.Role
	}
	return identity.Principal{TenantID: tenantID, UserID: userID, Email: email, Role: row.Role}, nil
}

func (s *Service) ListTenantMembers(ctx context.Context, tenantID string) ([]identity.Principal, error) {
	var rows []struct {
		TenantID string  `gorm:"column:tenant_id"`
		UserID   string  `gorm:"column:user_id"`
		Email    *string `gorm:"column:email"`
		Role     string  `gorm:"column:role"`
	}
	err := s.db.WithContext(ctx).
		Model(&tenantMemberModel{}).
		Select("tenant_members.tenant_id, tenant_members.user_id, users.email, tenant_members.role").
		Joins("JOIN users ON users.id = tenant_members.user_id").
		Where("tenant_members.tenant_id = ?", tenantID).
		Order("tenant_members.created_at ASC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	items := make([]identity.Principal, 0, len(rows))
	for _, row := range rows {
		email := ""
		if row.Email != nil {
			email = *row.Email
		}
		items = append(items, identity.Principal{TenantID: row.TenantID, UserID: row.UserID, Email: email, Role: row.Role})
	}
	return items, nil
}

func (s *Service) issueTokenPair(ctx context.Context, userID, tenantID, role, remoteAddr, userAgent string) (TokenPair, error) {
	accessToken, expiresAt, err := s.buildAccessToken(userID, tenantID, role)
	if err != nil {
		return TokenPair{}, err
	}
	refresh := randomToken(32)
	now := time.Now().UTC()
	err = s.db.WithContext(ctx).Create(&refreshTokenModel{
		ID:        "rt_" + randomID(12),
		UserID:    userID,
		TenantID:  tenantID,
		TokenHash: hashToken(refresh),
		IssuedAt:  now,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
		UserAgent: userAgent,
		IP:        remoteAddr,
	}).Error
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
		RefreshToken: refresh,
	}, nil
}

func (s *Service) buildAccessToken(userID, tenantID, role string) (string, time.Time, error) {
	now := time.Now().UTC()
	expires := now.Add(s.cfg.AccessTokenTTL)
	claims := jwt.MapClaims{
		"sub":       userID,
		"tenant_id": tenantID,
		"role":      role,
		"iat":       now.Unix(),
		"exp":       expires.Unix(),
		"jti":       "jti_" + randomID(10),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.cfg.JWTSigningKey))
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expires, nil
}

func validateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("invalid email")
	}
	return nil
}

func validateCNPhone(phone string) error {
	if phone == "" {
		return errors.New("phone is required")
	}
	if !cnPhonePattern.MatchString(phone) {
		return errors.New("invalid phone")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if !passwordHasLetter.MatchString(password) || !passwordHasDigit.MatchString(password) {
		return errors.New("password must contain letters and digits")
	}
	return nil
}

func formatPGInterval(d time.Duration) string {
	seconds := int(d / time.Second)
	if seconds <= 0 {
		seconds = 1
	}
	return fmt.Sprintf("%d seconds", seconds)
}

func randomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomDigits(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n)
	for i := range out {
		out[i] = '0' + (b[i] % 10)
	}
	return string(out)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	type sqlStateErr interface {
		SQLState() string
	}
	var stateErr sqlStateErr
	if errors.As(err, &stateErr) {
		return stateErr.SQLState() == "23505"
	}
	if strings.Contains(err.Error(), "SQLSTATE 23505") {
		return true
	}
	return false
}

func (s *Service) recordAudit(ctx context.Context, event models.AuditEvent) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Record(ctx, event)
}

func (s *Service) ensureLiteLLMProvisioned(ctx context.Context, userID, tenantID, remoteAddr, userAgent, trigger string) {
	if s.provisioner == nil {
		return
	}
	if err := s.provisioner.EnsureUserProvisioned(ctx, tenantID, userID); err != nil {
		s.logger.Warn("litellm auto provision failed", zap.String("trigger", trigger), zap.String("tenant_id", tenantID), zap.String("user_id", userID), zap.Error(err))
		s.recordAudit(ctx, models.AuditEvent{
			Actor:     userID,
			Action:    "litellm_auto_provision_" + trigger,
			Resource:  "litellm_key",
			Result:    "fail",
			TenantID:  tenantID,
			IP:        remoteAddr,
			UserAgent: userAgent,
		})
		return
	}
	s.logger.Info("litellm auto provision success", zap.String("trigger", trigger), zap.String("tenant_id", tenantID), zap.String("user_id", userID))
	s.recordAudit(ctx, models.AuditEvent{
		Actor:     userID,
		Action:    "litellm_auto_provision_" + trigger,
		Resource:  "litellm_key",
		Result:    "success",
		TenantID:  tenantID,
		IP:        remoteAddr,
		UserAgent: userAgent,
	})
}
