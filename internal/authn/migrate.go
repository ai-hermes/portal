package authn

import (
	"context"

	"gorm.io/gorm"
)

func Migrate(ctx context.Context, db *gorm.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE,
			phone TEXT,
			password_hash TEXT NOT NULL,
			display_name TEXT NOT NULL DEFAULT '',
			email_verified_at TIMESTAMPTZ,
			phone_verified_at TIMESTAMPTZ,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified_at TIMESTAMPTZ`,
		`ALTER TABLE users ALTER COLUMN email DROP NOT NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_unique ON users (phone) WHERE phone IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS tenants (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tenant_members (
			tenant_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (tenant_id, user_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tenant_members_user_id ON tenant_members (user_id)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			issued_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ,
			user_agent TEXT NOT NULL DEFAULT '',
			ip TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens (expires_at)`,
		`CREATE TABLE IF NOT EXISTS email_verifications (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications (user_id)`,
		`CREATE TABLE IF NOT EXISTS sms_verifications (
			id TEXT PRIMARY KEY,
			phone TEXT NOT NULL,
			purpose TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL,
			request_ip TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sms_verifications_phone_purpose ON sms_verifications (phone, purpose, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_sms_verifications_request_ip ON sms_verifications (request_ip, purpose, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS password_resets (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets (token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_expires_at ON password_resets (expires_at)`,
		`CREATE TABLE IF NOT EXISTS litellm_user_keys (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			api_key TEXT NOT NULL UNIQUE,
			key_alias TEXT NOT NULL DEFAULT '',
			last_budget_total DOUBLE PRECISION NOT NULL DEFAULT 0,
			last_spend_used DOUBLE PRECISION NOT NULL DEFAULT 0,
			last_synced_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			UNIQUE (tenant_id, user_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_litellm_user_keys_tenant_id ON litellm_user_keys (tenant_id)`,
		`CREATE TABLE IF NOT EXISTS litellm_credit_events (
			id BIGSERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			actor_user_id TEXT NOT NULL,
			actor_email TEXT NOT NULL DEFAULT '',
			mode TEXT NOT NULL,
			amount DOUBLE PRECISION NOT NULL,
			before_budget DOUBLE PRECISION NOT NULL DEFAULT 0,
			after_budget DOUBLE PRECISION NOT NULL DEFAULT 0,
			result TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_litellm_credit_events_tenant_user_time ON litellm_credit_events (tenant_id, user_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_litellm_credit_events_created_at ON litellm_credit_events (created_at DESC)`,
	}

	for _, stmt := range stmts {
		if err := db.WithContext(ctx).Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
}
