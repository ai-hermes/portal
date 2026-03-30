package authn

import (
	"context"

	"go.uber.org/zap"
)

type LogEmailProvider struct {
	logger *zap.Logger
}

func NewLogEmailProvider(logger *zap.Logger) *LogEmailProvider {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &LogEmailProvider{logger: logger.Named("email_provider")}
}

func (p *LogEmailProvider) SendVerificationCode(_ context.Context, email, code string) error {
	p.logger.Info("send email verification code", zap.String("email", email), zap.String("code", code))
	return nil
}

func (p *LogEmailProvider) SendPasswordResetToken(_ context.Context, email, token string) error {
	p.logger.Info("send password reset token", zap.String("email", email), zap.String("token", token))
	return nil
}
