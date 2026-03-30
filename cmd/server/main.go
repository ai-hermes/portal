package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/warjiang/portal/internal/api"
	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/authn"
	"github.com/warjiang/portal/internal/authz"
	"github.com/warjiang/portal/internal/litellm"
	"github.com/warjiang/portal/internal/litellmcredit"
	"github.com/warjiang/portal/internal/logging"
	"github.com/warjiang/portal/internal/providers/auditmem"
	"github.com/warjiang/portal/internal/providers/authzmem"
	"github.com/warjiang/portal/internal/providers/authzopenfga"
	"github.com/warjiang/portal/internal/providers/smsaliyun"
	"go.uber.org/zap"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// @title AI-Hermes Portal API
// @version 1.0
// @description AI-Hermes Portal backend APIs.
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	bootstrapLogger := mustNewLogger(logging.Config{Level: "info", Format: "console"})
	defer logging.Sync(bootstrapLogger)

	loadDotenvFiles(bootstrapLogger)

	logger := buildRuntimeLogger(bootstrapLogger)
	defer logging.Sync(logger)

	db, err := gorm.Open(postgres.Open(envOr("DATABASE_URL", "postgres://openfga:openfga@localhost:5432/openfga?sslmode=disable")), &gorm.Config{})
	if err != nil {
		logger.Fatal("open database failed", zap.Error(err))
	}
	sqlDB, err := db.DB()
	if err != nil {
		logger.Fatal("get std database failed", zap.Error(err))
	}
	defer sqlDB.Close()
	if err := sqlDB.Ping(); err != nil {
		logger.Fatal("ping database failed", zap.Error(err))
	}
	if err := authn.Migrate(context.Background(), db); err != nil {
		logger.Fatal("run auth migrations failed", zap.Error(err))
	}

	auditStore := auditmem.NewStore()
	auditSvc := audit.NewService(auditStore)
	authzProvider := selectAuthzProvider(logger)
	smsProvider := selectSMSProvider(logger)
	emailProvider := authn.NewLogEmailProvider(logger)
	liteLLMCreditSvc := buildLiteLLMCreditService(db, logger)
	authnSvc, err := authn.NewService(db, authn.Config{
		JWTSigningKey:     envOr("JWT_SIGNING_KEY", "dev-only-change-me"),
		AccessTokenTTL:    parseDurationOr(logger, "ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:   parseDurationOr(logger, "REFRESH_TOKEN_TTL", 30*24*time.Hour),
		EmailCodeTTL:      parseDurationOr(logger, "EMAIL_CODE_TTL", 10*time.Minute),
		SMSCodeTTL:        parseDurationOr(logger, "SMS_CODE_TTL", 10*time.Minute),
		SMSRateWindow:     parseDurationOr(logger, "SMS_RATE_WINDOW", 10*time.Minute),
		SMSResendInterval: parseDurationOr(logger, "SMS_RESEND_INTERVAL", 60*time.Second),
		SMSMaxPerPhone:    parseIntOr(logger, "SMS_MAX_PER_PHONE", 5),
		SMSMaxPerIP:       parseIntOr(logger, "SMS_MAX_PER_IP", 20),
		PasswordResetTTL:  parseDurationOr(logger, "PASSWORD_RESET_TTL", 15*time.Minute),
	}, emailProvider, smsProvider, auditSvc, liteLLMCreditSvc, logger)
	if err != nil {
		logger.Fatal("create auth service failed", zap.Error(err))
	}

	authzSvc := authz.NewService(authzProvider)

	router := api.NewRouter(api.Dependencies{
		Authn:          authnSvc,
		Authz:          authzSvc,
		Audit:          auditSvc,
		LiteLLMCredit:  liteLLMCreditSvc,
		SwaggerEnabled: parseBoolOr(logger, "SWAGGER_ENABLED", false),
		Logger:         logger,
	})
	webDir := envOr("WEB_DIST_DIR", "frontend/dist")
	handler := api.NewAppHandler(router, webDir)
	if handler == router {
		logger.Warn("frontend assets unavailable, serving API only", zap.String("web_dir", webDir))
	} else {
		if abs, absErr := filepath.Abs(webDir); absErr == nil {
			webDir = abs
		}
		logger.Info("serving frontend assets", zap.String("web_dir", webDir))
	}

	srv := &http.Server{
		Addr:              envOr("PORT", ":8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.Info("portal backend listening", zap.String("addr", srv.Addr))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("server failed", zap.Error(err))
	}
}

func mustNewLogger(cfg logging.Config) *zap.Logger {
	logger, err := logging.New(cfg)
	if err != nil {
		panic(err)
	}
	return logger
}

func buildRuntimeLogger(fallback *zap.Logger) *zap.Logger {
	cfg := logging.Config{
		Level:  strings.TrimSpace(os.Getenv("LOG_LEVEL")),
		Format: strings.TrimSpace(envOr("LOG_FORMAT", "json")),
	}
	logger, err := logging.New(cfg)
	if err != nil {
		fallback.Warn(
			"init runtime logger failed, fallback to json/info",
			zap.Error(err),
			zap.String("log_level", cfg.Level),
			zap.String("log_format", cfg.Format),
		)
		logger = mustNewLogger(logging.Config{Level: "info", Format: "json"})
	}
	logger.Info("logger initialized", zap.String("log_level", envOr("LOG_LEVEL", "info")), zap.String("log_format", envOr("LOG_FORMAT", "json")))
	return logger
}

func buildLiteLLMCreditService(db *gorm.DB, logger *zap.Logger) *litellmcredit.Service {
	baseURL := strings.TrimSpace(envOr("LITELLM_BASE_URL", "https://llmv2.spotty.com.cn/"))
	masterKey := strings.TrimSpace(os.Getenv("LITELLM_MASTER_KEY"))
	if masterKey == "" {
		logger.Info("litellm credit service disabled", zap.String("reason", "missing LITELLM_MASTER_KEY"))
		return nil
	}

	client, err := litellm.NewClient(litellm.Config{
		BaseURL:   baseURL,
		MasterKey: masterKey,
		HTTPClient: &http.Client{
			Timeout: parseDurationOr(logger, "LITELLM_HTTP_TIMEOUT", 5*time.Second),
		},
	})
	if err != nil {
		logger.Warn("litellm credit service disabled: create client failed", zap.Error(err))
		return nil
	}

	service, err := litellmcredit.NewService(db, client, litellmcredit.Config{
		PlatformAdminEmails: litellmcredit.ParsePlatformAdminEmails(os.Getenv("PLATFORM_ADMIN_EMAILS")),
		DefaultUserQuota:    parseFloatOr(logger, "LITELLM_DEFAULT_USER_QUOTA", 10),
	})
	if err != nil {
		logger.Warn("litellm credit service disabled: create service failed", zap.Error(err))
		return nil
	}
	logger.Info("litellm credit service enabled")
	return service
}

func loadDotenvFiles(logger *zap.Logger) {
	files := dotenvFiles()
	logger.Info("dotenv load start", zap.Strings("files", files))

	totalSet := 0
	totalSkipped := 0
	for _, file := range files {
		values, err := godotenv.Read(file)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				logger.Debug("dotenv file missing", zap.String("file", file))
				continue
			}
			logger.Warn("dotenv read failed", zap.String("file", file), zap.Error(err))
			continue
		}

		keys := make([]string, 0, len(values))
		setCount := 0
		skippedCount := 0
		for key, value := range values {
			keys = append(keys, key)
			if _, exists := os.LookupEnv(key); exists {
				skippedCount++
				continue
			}
			if err := os.Setenv(key, value); err != nil {
				logger.Warn("dotenv set failed", zap.String("file", file), zap.String("key", key), zap.Error(err))
				continue
			}
			setCount++
		}

		sort.Strings(keys)
		totalSet += setCount
		totalSkipped += skippedCount
		logger.Info(
			"dotenv loaded",
			zap.String("file", file),
			zap.Int("parsed", len(values)),
			zap.Int("set", setCount),
			zap.Int("skipped", skippedCount),
			zap.Strings("keys", keys),
		)
	}

	logger.Info("dotenv load done", zap.Int("set", totalSet), zap.Int("skipped", totalSkipped))
}

func dotenvFiles() []string {
	raw := strings.TrimSpace(os.Getenv("DOTENV_FILES"))
	if raw == "" {
		return []string{".env.local", ".env"}
	}
	parts := strings.Split(raw, ",")
	files := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		file := strings.TrimSpace(part)
		if file == "" {
			continue
		}
		if _, ok := seen[file]; ok {
			continue
		}
		seen[file] = struct{}{}
		files = append(files, file)
	}
	if len(files) == 0 {
		return []string{".env.local", ".env"}
	}
	return files
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseDurationOr(logger *zap.Logger, key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		logger.Warn("invalid duration, using fallback", zap.String("key", key), zap.String("raw", raw), zap.Duration("fallback", fallback))
		return fallback
	}
	return parsed
}

func parseIntOr(logger *zap.Logger, key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		logger.Warn("invalid int, using fallback", zap.String("key", key), zap.String("raw", raw), zap.Int("fallback", fallback))
		return fallback
	}
	return parsed
}

func parseBoolOr(logger *zap.Logger, key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		logger.Warn("invalid bool, using fallback", zap.String("key", key), zap.String("raw", raw), zap.Bool("fallback", fallback))
		return fallback
	}
	return parsed
}

func parseFloatOr(logger *zap.Logger, key string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		logger.Warn("invalid float, using fallback", zap.String("key", key), zap.String("raw", raw), zap.Float64("fallback", fallback))
		return fallback
	}
	return parsed
}

func selectAuthzProvider(logger *zap.Logger) authz.Provider {
	switch envOr("AUTHZ_PROVIDER", "memory") {
	case "openfga":
		apiURL := envOr("OPENFGA_API_URL", "http://localhost:8081")
		storeID := os.Getenv("OPENFGA_STORE_ID")
		if storeID == "" {
			logger.Warn("AUTHZ_PROVIDER=openfga but OPENFGA_STORE_ID is empty, fallback to memory")
			return authzmem.NewProvider()
		}
		logger.Info("using OpenFGA authz provider", zap.String("api_url", apiURL), zap.String("store_id", storeID))
		return authzopenfga.NewProvider(apiURL, storeID)
	default:
		logger.Info("using in-memory authz provider")
		return authzmem.NewProvider()
	}
}

func selectSMSProvider(logger *zap.Logger) authn.SMSProvider {
	switch envOr("SMS_PROVIDER", "log") {
	case "aliyun":
		provider, err := smsaliyun.NewProvider(smsaliyun.Config{
			RegionID:             envOr("ALIBABA_CLOUD_REGION_ID", "cn-hangzhou"),
			AccessKeyID:          os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"),
			AccessKeySecret:      os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
			SignName:             os.Getenv("ALIYUN_SMS_SIGN_NAME"),
			RegisterTemplateCode: os.Getenv("ALIYUN_SMS_TEMPLATE_CODE_REGISTER"),
		}, logger)
		if err != nil {
			logger.Warn("init aliyun sms provider failed, fallback to log provider", zap.Error(err))
			return authn.NewLogSMSProvider(logger)
		}
		logger.Info("using aliyun sms provider")
		return provider
	default:
		logger.Info("using log sms provider")
		return authn.NewLogSMSProvider(logger)
	}
}
