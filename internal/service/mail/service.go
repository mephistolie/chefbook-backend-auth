package mail

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/assets"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-auth/pkg/ip"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/mail"
	"github.com/mssola/useragent"
	"time"
)

const (
	mailSendAttempts = 3
)

type routeTemplates struct {
	profileActivation string
	passwordReset     string
}

type profileActivationMailValues struct {
	ActivationCode string
	ActivationLink string
}

type newProfileLoginValues struct {
	IP        string
	Access    string
	Location  string
	Timestamp string
}

type passwordResetValues struct {
	ResetLink string
}

type nicknameChangedValue struct {
	Nickname string
}

type Service struct {
	sender         mail.Sender
	routeTemplates routeTemplates
	ipInfoProvider ip.InfoProvider
	IsStub         bool
}

func NewService(ipInfoProvider ip.InfoProvider, cfg *config.Config) (*Service, error) {
	var mailSender mail.Sender = mail.NewStubSender()
	var err error = nil
	if len(*cfg.Smtp.Host) > 0 {
		if mailSender, err = mail.NewSmtpSender(
			*cfg.Smtp.Sender,
			*cfg.Smtp.Password,
			*cfg.Smtp.Host,
			*cfg.Smtp.Port,
			30*time.Second,
		); err != nil {
			return nil, err
		}
	}
	return &Service{
		sender: mailSender,
		routeTemplates: routeTemplates{
			profileActivation: fmt.Sprintf("%s/%s", *cfg.BackendUrl, *cfg.Smtp.ProfileActivationRouteTmpl),
			passwordReset:     fmt.Sprintf("%s/%s", *cfg.FrontendUrl, *cfg.Smtp.PasswordResetRouteTmpl),
		},
		ipInfoProvider: ipInfoProvider,
		IsStub:         len(*cfg.Smtp.Host) == 0,
	}, nil
}

func (s *Service) SendProfileActivationMail(userId uuid.UUID, email string, code string) {
	log.Info("sending profile activation mail to ", email)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Activation",
	}
	mailValues := profileActivationMailValues{
		ActivationCode: code,
		ActivationLink: fmt.Sprintf(s.routeTemplates.profileActivation, userId, code),
	}
	if err := payload.SetHtmlBody(assets.ProfileActivationMailTmplFilePath, mailValues); err != nil {
		log.Error("failed to set HTML Body for mail: ", err)
	}
	_ = s.sender.Send(payload, mailSendAttempts)
}

func (s *Service) SendNewLoginMail(email string, client entity.ClientData, timestamp time.Time) {
	log.Info("sending new login mail to ", email)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook New Profile Login",
	}
	ua := useragent.New(client.UserAgent)
	var access string
	if ua.Mobile() {
		access = ua.Model()
	} else {
		browser, version := ua.Browser()
		access = fmt.Sprintf("%s %s, %s", browser, version, ua.OS())
	}
	mailValues := newProfileLoginValues{
		IP:        client.Ip,
		Access:    access,
		Location:  s.ipInfoProvider.GetLocation(client.Ip),
		Timestamp: timestamp.Format(time.RFC1123),
	}
	if err := payload.SetHtmlBody(assets.NewLoginFilePath, mailValues); err != nil {
		log.Error("failed to set HTML Body for mail: ", err)
	}
	_ = s.sender.Send(payload, mailSendAttempts)
}

func (s *Service) SendResetPasswordMail(userId uuid.UUID, email string, code string) {
	log.Info("sending password reset mail to ", email)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Password Reset",
	}
	mailValues := passwordResetValues{
		ResetLink: fmt.Sprintf(s.routeTemplates.passwordReset, userId, code),
	}
	if err := payload.SetHtmlBody(assets.PasswordResetMailTmplFilePath, mailValues); err != nil {
		log.Error("failed to set HTML Body for mail: ", err)
	}
	_ = s.sender.Send(payload, mailSendAttempts)
}

func (s *Service) SendPasswordChangedMail(email string) {
	log.Info("sending password changed mail to ", email)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Password Update",
	}
	if err := payload.SetHtmlBody(assets.PasswordChangedMailTmplFilePath, nil); err != nil {
		log.Error("failed to set HTML Body for mail: ", err)
	}
	_ = s.sender.Send(payload, mailSendAttempts)
}

func (s *Service) SendNicknameChangedMail(email, nickname string) {
	log.Info("sending nickname changed mail to ", email)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Nickname Update",
	}
	mailValues := nicknameChangedValue{
		Nickname: nickname,
	}
	if err := payload.SetHtmlBody(assets.NicknameChangedMailTmplFilePath, mailValues); err != nil {
		log.Error("failed to set HTML Body for mail: ", err)
	}
	_ = s.sender.Send(payload, mailSendAttempts)
}
