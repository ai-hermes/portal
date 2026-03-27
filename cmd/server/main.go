package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/warjiang/portal/internal/api"
	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/authn"
	"github.com/warjiang/portal/internal/authz"
	"github.com/warjiang/portal/internal/providers/auditmem"
	"github.com/warjiang/portal/internal/providers/authzmem"
	"github.com/warjiang/portal/internal/providers/authzopenfga"
	"github.com/warjiang/portal/internal/providers/smsaliyun"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(postgres.Open(envOr("DATABASE_URL", "postgres://openfga:openfga@localhost:5432/openfga?sslmode=disable")), &gorm.Config{})
	if err != nil {
		log.Fatalf("open database failed: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("get std database failed: %v", err)
	}
	defer sqlDB.Close()
	if err := sqlDB.Ping(); err != nil {
		log.Fatalf("ping database failed: %v", err)
	}
	if err := authn.Migrate(context.Background(), db); err != nil {
		log.Fatalf("run auth migrations failed: %v", err)
	}

	auditStore := auditmem.NewStore()
	auditSvc := audit.NewService(auditStore)
	authzProvider := selectAuthzProvider()
	smsProvider := selectSMSProvider()
	authnSvc, err := authn.NewService(db, authn.Config{
		JWTSigningKey:     envOr("JWT_SIGNING_KEY", "dev-only-change-me"),
		AccessTokenTTL:    parseDurationOr("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:   parseDurationOr("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		EmailCodeTTL:      parseDurationOr("EMAIL_CODE_TTL", 10*time.Minute),
		SMSCodeTTL:        parseDurationOr("SMS_CODE_TTL", 10*time.Minute),
		SMSRateWindow:     parseDurationOr("SMS_RATE_WINDOW", 10*time.Minute),
		SMSResendInterval: parseDurationOr("SMS_RESEND_INTERVAL", 60*time.Second),
		SMSMaxPerPhone:    parseIntOr("SMS_MAX_PER_PHONE", 5),
		SMSMaxPerIP:       parseIntOr("SMS_MAX_PER_IP", 20),
		PasswordResetTTL:  parseDurationOr("PASSWORD_RESET_TTL", 15*time.Minute),
	}, authn.NewLogEmailProvider(), smsProvider, auditSvc)
	if err != nil {
		log.Fatalf("create auth service failed: %v", err)
	}

	authzSvc := authz.NewService(authzProvider)

	router := api.NewRouter(api.Dependencies{
		Authn: authnSvc,
		Authz: authzSvc,
		Audit: auditSvc,
	})
	webDir := envOr("WEB_DIST_DIR", "frontend/dist")
	handler := api.NewAppHandler(router, webDir)
	if handler == router {
		log.Printf("frontend assets unavailable at %s, serving API only", webDir)
	} else {
		if abs, err := filepath.Abs(webDir); err == nil {
			webDir = abs
		}
		log.Printf("serving frontend assets from %s", webDir)
	}

	srv := &http.Server{
		Addr:              envOr("PORT", ":8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("portal backend listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseDurationOr(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("invalid duration for %s=%s, fallback=%s", key, raw, fallback)
		return fallback
	}
	return parsed
}

func parseIntOr(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("invalid int for %s=%s, fallback=%d", key, raw, fallback)
		return fallback
	}
	return parsed
}

func selectAuthzProvider() authz.Provider {
	switch envOr("AUTHZ_PROVIDER", "memory") {
	case "openfga":
		apiURL := envOr("OPENFGA_API_URL", "http://localhost:8081")
		storeID := os.Getenv("OPENFGA_STORE_ID")
		if storeID == "" {
			log.Printf("AUTHZ_PROVIDER=openfga but OPENFGA_STORE_ID is empty, fallback to memory")
			return authzmem.NewProvider()
		}
		log.Printf("using OpenFGA authz provider: api_url=%s store_id=%s", apiURL, storeID)
		return authzopenfga.NewProvider(apiURL, storeID)
	default:
		log.Printf("using in-memory authz provider")
		return authzmem.NewProvider()
	}
}

func selectSMSProvider() authn.SMSProvider {
	switch envOr("SMS_PROVIDER", "log") {
	case "aliyun":
		provider, err := smsaliyun.NewProvider(smsaliyun.Config{
			RegionID:             envOr("ALIBABA_CLOUD_REGION_ID", "cn-hangzhou"),
			AccessKeyID:          os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"),
			AccessKeySecret:      os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
			SignName:             os.Getenv("ALIYUN_SMS_SIGN_NAME"),
			RegisterTemplateCode: os.Getenv("ALIYUN_SMS_TEMPLATE_CODE_REGISTER"),
		})
		if err != nil {
			log.Printf("init aliyun sms provider failed: %v, fallback to log provider", err)
			return authn.NewLogSMSProvider()
		}
		log.Printf("using aliyun sms provider")
		return provider
	default:
		log.Printf("using log sms provider")
		return authn.NewLogSMSProvider()
	}
}
