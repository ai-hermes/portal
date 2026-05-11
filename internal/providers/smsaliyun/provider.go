package smsaliyun

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
	"go.uber.org/zap"
)

type Config struct {
	RegionID                  string
	AccessKeyID               string
	AccessKeySecret           string
	SignName                  string
	RegisterTemplateCode      string
	PasswordResetTemplateCode string
}

type Provider struct {
	client                    *dysmsapi.Client
	signName                  string
	registerTemplateCode      string
	passwordResetTemplateCode string
	logger                    *zap.Logger
}

func NewProvider(cfg Config, logger *zap.Logger) (*Provider, error) {
	if cfg.RegionID == "" {
		cfg.RegionID = "cn-hangzhou"
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.Named("sms_aliyun")

	if cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" {
		logger.Error("init aliyun sms provider failed: missing access key")
		return nil, fmt.Errorf("aliyun sms access key is required")
	}
	if cfg.SignName == "" {
		logger.Error("init aliyun sms provider failed: missing sign name")
		return nil, fmt.Errorf("aliyun sms sign name is required")
	}
	if cfg.RegisterTemplateCode == "" {
		logger.Error("init aliyun sms provider failed: missing register template code")
		return nil, fmt.Errorf("aliyun sms register template code is required")
	}
	if cfg.PasswordResetTemplateCode == "" {
		logger.Error("init aliyun sms provider failed: missing password reset template code")
		return nil, fmt.Errorf("aliyun sms password reset template code is required")
	}

	client, err := dysmsapi.NewClientWithAccessKey(cfg.RegionID, cfg.AccessKeyID, cfg.AccessKeySecret)
	if err != nil {
		logger.Error("init aliyun sms provider failed: create client error", zap.String("region_id", cfg.RegionID), zap.Error(err))
		return nil, err
	}
	logger.Info("aliyun sms provider initialized", zap.String("region_id", cfg.RegionID), zap.String("sign_name", cfg.SignName), zap.String("register_template_code", cfg.RegisterTemplateCode), zap.String("password_reset_template_code", cfg.PasswordResetTemplateCode))

	return &Provider{
		client:                    client,
		signName:                  cfg.SignName,
		registerTemplateCode:      cfg.RegisterTemplateCode,
		passwordResetTemplateCode: cfg.PasswordResetTemplateCode,
		logger:                    logger,
	}, nil
}

func (p *Provider) SendRegisterCode(_ context.Context, phone, code string) error {
	return p.sendCode(phone, code, p.registerTemplateCode, "register")
}

func (p *Provider) SendPasswordResetCode(_ context.Context, phone, code string) error {
	return p.sendCode(phone, code, p.passwordResetTemplateCode, "password_reset")
}

func (p *Provider) sendCode(phone, code, templateCode, purpose string) error {
	p.logger.Info("aliyun sms send code start", zap.String("phone", phone), zap.String("purpose", purpose), zap.String("template_code", templateCode), zap.String("sign_name", p.signName))
	params, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		p.logger.Error("aliyun sms send code marshal params failed", zap.String("phone", phone), zap.String("purpose", purpose), zap.Error(err))
		return err
	}

	req := dysmsapi.CreateSendSmsRequest()
	req.Scheme = "https"
	req.PhoneNumbers = phone
	req.SignName = p.signName
	req.TemplateCode = templateCode
	req.TemplateParam = string(params)

	resp, err := p.client.SendSms(req)
	if err != nil {
		p.logger.Error("aliyun sms send code request failed", zap.String("phone", phone), zap.String("purpose", purpose), zap.Error(err))
		return err
	}
	if resp.Code != "OK" {
		p.logger.Warn("aliyun sms send code rejected", zap.String("phone", phone), zap.String("purpose", purpose), zap.String("resp_code", resp.Code), zap.String("resp_message", resp.Message), zap.String("request_id", resp.RequestId), zap.String("biz_id", resp.BizId))
		return fmt.Errorf("aliyun sms send failed: code=%s message=%s request_id=%s", resp.Code, resp.Message, resp.RequestId)
	}
	p.logger.Info("aliyun sms send code success", zap.String("phone", phone), zap.String("purpose", purpose), zap.String("request_id", resp.RequestId), zap.String("biz_id", resp.BizId))
	return nil
}
