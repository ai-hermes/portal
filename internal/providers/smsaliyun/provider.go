package smsaliyun

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
)

type Config struct {
	RegionID             string
	AccessKeyID          string
	AccessKeySecret      string
	SignName             string
	RegisterTemplateCode string
}

type Provider struct {
	client               *dysmsapi.Client
	signName             string
	registerTemplateCode string
}

func NewProvider(cfg Config) (*Provider, error) {
	if cfg.RegionID == "" {
		cfg.RegionID = "cn-hangzhou"
	}
	if cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" {
		return nil, fmt.Errorf("aliyun sms access key is required")
	}
	if cfg.SignName == "" {
		return nil, fmt.Errorf("aliyun sms sign name is required")
	}
	if cfg.RegisterTemplateCode == "" {
		return nil, fmt.Errorf("aliyun sms register template code is required")
	}

	client, err := dysmsapi.NewClientWithAccessKey(cfg.RegionID, cfg.AccessKeyID, cfg.AccessKeySecret)
	if err != nil {
		return nil, err
	}

	return &Provider{
		client:               client,
		signName:             cfg.SignName,
		registerTemplateCode: cfg.RegisterTemplateCode,
	}, nil
}

func (p *Provider) SendRegisterCode(_ context.Context, phone, code string) error {
	params, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return err
	}

	req := dysmsapi.CreateSendSmsRequest()
	req.Scheme = "https"
	req.PhoneNumbers = phone
	req.SignName = p.signName
	req.TemplateCode = p.registerTemplateCode
	req.TemplateParam = string(params)

	resp, err := p.client.SendSms(req)
	if err != nil {
		return err
	}
	if resp.Code != "OK" {
		return fmt.Errorf("aliyun sms send failed: code=%s message=%s request_id=%s", resp.Code, resp.Message, resp.RequestId)
	}
	return nil
}
