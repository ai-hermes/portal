package authn

import (
	"context"

	"go.uber.org/zap"
)

type LogSMSProvider struct {
	logger *zap.Logger
}

func NewLogSMSProvider(logger *zap.Logger) *LogSMSProvider {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &LogSMSProvider{logger: logger.Named("sms_provider")}
}

func (p *LogSMSProvider) SendRegisterCode(_ context.Context, phone, code string) error {
	p.logger.Info("send register sms code", zap.String("phone", phone), zap.String("code", code))
	return nil
}
