package authn

import (
	"context"
	"log"
)

type LogEmailProvider struct{}

func NewLogEmailProvider() *LogEmailProvider {
	return &LogEmailProvider{}
}

func (p *LogEmailProvider) SendVerificationCode(_ context.Context, email, code string) error {
	log.Printf("[email][verify] email=%s code=%s", email, code)
	return nil
}

func (p *LogEmailProvider) SendPasswordResetToken(_ context.Context, email, token string) error {
	log.Printf("[email][reset] email=%s token=%s", email, token)
	return nil
}
