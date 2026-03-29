package authn

import (
	"context"
	"log"
)

type LogSMSProvider struct{}

func NewLogSMSProvider() *LogSMSProvider {
	return &LogSMSProvider{}
}

func (p *LogSMSProvider) SendRegisterCode(_ context.Context, phone, code string) error {
	log.Printf("[sms][register] phone=%s code=%s", phone, code)
	return nil
}
