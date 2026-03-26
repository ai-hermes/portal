package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/models"
	"golang.org/x/crypto/bcrypt"
)

var (
	passwordHasLetter = regexp.MustCompile(`[A-Za-z]`)
	passwordHasDigit  = regexp.MustCompile(`[0-9]`)
)

type Config struct {
	JWTSigningKey       string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	EmailCodeTTL        time.Duration
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

type Service struct {
	db    *sql.DB
	cfg   Config
	email EmailProvider
	audit *audit.Service
}

func NewService(db *sql.DB, cfg Config, email EmailProvider, auditSvc *audit.Service) (*Service, error) {
	cfg = cfg.withDefaults()
	if strings.TrimSpace(cfg.JWTSigningKey) == "" {
		return nil, errors.New("JWT_SIGNING_KEY is required")
	}
	if email == nil {
		return nil, errors.New("email provider is required")
	}
	if db == nil {
		return nil, errors.New("db is required")
	}
	return &Service{db: db, cfg: cfg, email: email, audit: auditSvc}, nil
}

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

func (s *Service) Register(ctx context.Context, in RegisterInput, remoteAddr, userAgent string) (RegisterResult, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if err := validateEmail(email); err != nil {
		return RegisterResult{}, apiError(400, "invalid_email", err.Error())
	}
	if err := validatePassword(in.Password); err != nil {
		return RegisterResult{}, apiError(400, "weak_password", err.Error())
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), s.cfg.BcryptCost)
	if err != nil {
		return RegisterResult{}, err
	}

	userID := "u_" + randomID(12)
	tenantID := fmt.Sprintf("%s-%s", s.cfg.DefaultTenantPrefix, randomID(8))
	now := time.Now().UTC()
	code := randomDigits(6)
	codeHash := hashToken(code)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RegisterResult{}, err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash, display_name, created_at, updated_at, status)
		VALUES ($1, $2, $3, $4, $5, $5, 'active')
	`, userID, email, string(hash), strings.TrimSpace(in.DisplayName), now)
	if err != nil {
		if isUniqueViolation(err) {
			return RegisterResult{}, apiError(409, "email_already_exists", "email already exists")
		}
		return RegisterResult{}, err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO tenants (id, name, created_by, created_at)
		VALUES ($1, $2, $3, $4)
	`, tenantID, "Personal Workspace", userID, now)
	if err != nil {
		return RegisterResult{}, err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO tenant_members (tenant_id, user_id, role, created_at)
		VALUES ($1, $2, 'tenant_admin', $3)
	`, tenantID, userID, now)
	if err != nil {
		return RegisterResult{}, err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO email_verifications (id, user_id, code_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, "ev_"+randomID(12), userID, codeHash, now.Add(s.cfg.EmailCodeTTL), now)
	if err != nil {
		return RegisterResult{}, err
	}

	if err := tx.Commit(); err != nil {
		return RegisterResult{}, err
	}

	if err := s.email.SendVerificationCode(ctx, email, code); err != nil {
		log.Printf("send verification code failed: email=%s err=%v", email, err)
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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var userID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE email=$1`, email).Scan(&userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apiError(400, "invalid_verification_code", "invalid verification code")
		}
		return err
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE email_verifications
		SET used_at = NOW()
		WHERE user_id=$1
		  AND code_hash=$2
		  AND used_at IS NULL
		  AND expires_at > NOW()
	`, userID, hashToken(code))
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return apiError(400, "invalid_verification_code", "invalid verification code")
	}

	_, err = tx.ExecContext(ctx, `UPDATE users SET email_verified_at=NOW(), updated_at=NOW() WHERE id=$1`, userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Service) Login(ctx context.Context, email, password, remoteAddr, userAgent string) (TokenPair, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || strings.TrimSpace(password) == "" {
		return TokenPair{}, apiError(400, "invalid_request", "email and password are required")
	}

	var (
		userID          string
		passwordHash    string
		emailVerifiedAt sql.NullTime
		tenantID        string
		role            string
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.password_hash, u.email_verified_at, tm.tenant_id, tm.role
		FROM users u
		JOIN tenant_members tm ON tm.user_id=u.id
		WHERE u.email=$1
		ORDER BY tm.created_at ASC
		LIMIT 1
	`, email).Scan(&userID, &passwordHash, &emailVerifiedAt, &tenantID, &role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TokenPair{}, apiError(401, "invalid_credentials", "invalid email or password")
		}
		return TokenPair{}, err
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) != nil {
		s.recordAudit(ctx, models.AuditEvent{Actor: userID, Action: "auth_login", Resource: "session", Result: "deny", TenantID: tenantID, IP: remoteAddr, UserAgent: userAgent})
		return TokenPair{}, apiError(401, "invalid_credentials", "invalid email or password")
	}
	if !emailVerifiedAt.Valid {
		return TokenPair{}, apiError(403, "email_not_verified", "email is not verified")
	}

	pair, err := s.issueTokenPair(ctx, userID, tenantID, role, remoteAddr, userAgent)
	if err != nil {
		return TokenPair{}, err
	}

	s.recordAudit(ctx, models.AuditEvent{Actor: userID, Action: "auth_login", Resource: "session", Result: "success", TenantID: tenantID, IP: remoteAddr, UserAgent: userAgent})
	return pair, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken, remoteAddr, userAgent string) (TokenPair, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return TokenPair{}, apiError(400, "invalid_request", "refresh_token is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenPair{}, err
	}
	defer tx.Rollback()

	var (
		rowID    string
		userID   string
		tenantID string
		role     string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT rt.id, rt.user_id, rt.tenant_id, tm.role
		FROM refresh_tokens rt
		JOIN tenant_members tm ON tm.user_id=rt.user_id AND tm.tenant_id=rt.tenant_id
		WHERE rt.token_hash=$1
		  AND rt.revoked_at IS NULL
		  AND rt.expires_at > NOW()
	`, hashToken(refreshToken)).Scan(&rowID, &userID, &tenantID, &role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TokenPair{}, apiError(401, "invalid_refresh_token", "invalid refresh token")
		}
		return TokenPair{}, err
	}

	_, err = tx.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=NOW() WHERE id=$1`, rowID)
	if err != nil {
		return TokenPair{}, err
	}

	accessToken, expiresAt, err := s.buildAccessToken(userID, tenantID, role)
	if err != nil {
		return TokenPair{}, err
	}
	newRefresh := randomToken(32)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, issued_at, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7)
	`, "rt_"+randomID(12), userID, tenantID, hashToken(newRefresh), time.Now().UTC().Add(s.cfg.RefreshTokenTTL), userAgent, remoteAddr)
	if err != nil {
		return TokenPair{}, err
	}

	if err := tx.Commit(); err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
		RefreshToken: newRefresh,
	}, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	if strings.TrimSpace(refreshToken) == "" {
		return apiError(400, "invalid_request", "refresh_token is required")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL`, hashToken(refreshToken))
	return err
}

func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	if strings.TrimSpace(oldPassword) == "" || strings.TrimSpace(newPassword) == "" {
		return apiError(400, "invalid_request", "old_password and new_password are required")
	}
	if err := validatePassword(newPassword); err != nil {
		return apiError(400, "weak_password", err.Error())
	}

	var oldHash string
	if err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=$1`, userID).Scan(&oldHash); err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(oldPassword)) != nil {
		return apiError(401, "invalid_credentials", "old password is incorrect")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2`, string(newHash), userID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return err
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return apiError(400, "invalid_request", "email is required")
	}
	var userID string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE email=$1`, email).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}

	token := randomToken(32)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO password_resets (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, "pr_"+randomID(12), userID, hashToken(token), time.Now().UTC().Add(s.cfg.PasswordResetTTL))
	if err != nil {
		return err
	}
	if err := s.email.SendPasswordResetToken(ctx, email, token); err != nil {
		log.Printf("send reset token failed: email=%s err=%v", email, err)
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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var userID string
	err = tx.QueryRowContext(ctx, `
		SELECT user_id
		FROM password_resets
		WHERE token_hash=$1
		  AND used_at IS NULL
		  AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1
	`, hashToken(token)).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apiError(400, "invalid_reset_token", "invalid reset token")
		}
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2`, string(hash), userID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE password_resets SET used_at=NOW() WHERE token_hash=$1 AND used_at IS NULL`, hashToken(token))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return err
	}

	return tx.Commit()
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

	var email string
	var currentRole string
	err = s.db.QueryRowContext(ctx, `
		SELECT u.email, tm.role
		FROM users u
		JOIN tenant_members tm ON tm.user_id=u.id
		WHERE u.id=$1 AND tm.tenant_id=$2
		LIMIT 1
	`, userID, tenantID).Scan(&email, &currentRole)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return identity.Principal{}, apiError(401, "invalid_access_token", "invalid access token")
		}
		return identity.Principal{}, err
	}
	if role == "" {
		role = currentRole
	}
	return identity.Principal{TenantID: tenantID, UserID: userID, Email: email, Role: currentRole}, nil
}

func (s *Service) ListTenantMembers(ctx context.Context, tenantID string) ([]identity.Principal, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT tm.tenant_id, tm.user_id, u.email, tm.role
		FROM tenant_members tm
		JOIN users u ON u.id=tm.user_id
		WHERE tm.tenant_id=$1
		ORDER BY tm.created_at ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]identity.Principal, 0)
	for rows.Next() {
		var p identity.Principal
		if err := rows.Scan(&p.TenantID, &p.UserID, &p.Email, &p.Role); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}

func (s *Service) issueTokenPair(ctx context.Context, userID, tenantID, role, remoteAddr, userAgent string) (TokenPair, error) {
	accessToken, expiresAt, err := s.buildAccessToken(userID, tenantID, role)
	if err != nil {
		return TokenPair{}, err
	}
	refresh := randomToken(32)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, issued_at, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7)
	`, "rt_"+randomID(12), userID, tenantID, hashToken(refresh), time.Now().UTC().Add(s.cfg.RefreshTokenTTL), userAgent, remoteAddr)
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

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if !passwordHasLetter.MatchString(password) || !passwordHasDigit.MatchString(password) {
		return errors.New("password must contain letters and digits")
	}
	return nil
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
	return false
}

func (s *Service) recordAudit(ctx context.Context, event models.AuditEvent) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Record(ctx, event)
}
