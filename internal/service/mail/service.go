package mail

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/assets"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-auth/pkg/ip"
	"github.com/mephistolie/chefbook-backend-common/mail"
	"github.com/mssola/useragent"
)

const (
	mailKindProfileActivation      = "profile_activation"
	mailKindNewLogin               = "new_login"
	mailKindPasswordReset          = "password_reset"
	mailKindPasswordChanged        = "password_changed"
	mailKindUsernameChanged        = "username_changed"
	mailKindProfileDeletionRequest = "profile_deletion_request"
	mailKindProfileDeleted         = "profile_deleted"
)

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

type usernameChangedValue struct {
	Username string
}

type profileDeletionRequestValues struct {
	IncludeSharedData string
	Timestamp         string
}

type Service struct {
	sender         mail.Sender
	ipInfoProvider ip.InfoProvider
	IsStub         bool
	IsDevEnv       bool
	sendAttempts   int
}

func NewService(ipInfoProvider ip.InfoProvider, cfg *config.Config) (*Service, error) {
	var mailSender mail.Sender = mail.NewStubSender()
	var err error = nil
	if len(*cfg.Smtp.Host) > 0 {
		if mailSender, err = mail.NewSmtpSender(
			*cfg.Smtp.Email,
			*cfg.Smtp.Password,
			*cfg.Smtp.Host,
			*cfg.Smtp.Port,
			30*time.Second,
			*cfg.Smtp.Username,
		); err != nil {
			return nil, err
		}
	}
	return &Service{
		sender:         mailSender,
		ipInfoProvider: ipInfoProvider,
		IsStub:         len(*cfg.Smtp.Host) == 0,
		IsDevEnv:       *cfg.Environment == config.EnvDev,
		sendAttempts:   *cfg.Smtp.SendAttempts,
	}, nil
}

func (s *Service) SendProfileActivationMail(ctx context.Context, userId uuid.UUID, email, code, linkPattern string) {
	eventData := authlog.MailData{Kind: mailKindProfileActivation, UserID: userId.String()}
	authlog.Default.MailDeliveryStarted(ctx, eventData)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Activation",
	}
	mailValues := profileActivationMailValues{
		ActivationCode: code,
		ActivationLink: fmt.Sprintf(linkPattern, userId, code),
	}
	if err := payload.SetHtmlBody(assets.ProfileActivationMailTmplFilePath, mailValues); err != nil {
		authlog.Default.MailTemplateRenderFailed(ctx, eventData, err)
	}
	s.sendMessage(ctx, payload, eventData)
}

func (s *Service) SendNewLoginMail(ctx context.Context, userId uuid.UUID, email string, client entity.ClientData, timestamp time.Time) {
	eventData := authlog.MailData{Kind: mailKindNewLogin, UserID: userId.String()}
	authlog.Default.MailDeliveryStarted(ctx, eventData)
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
		authlog.Default.MailTemplateRenderFailed(ctx, eventData, err)
	}
	s.sendMessage(ctx, payload, eventData)
}

func (s *Service) SendResetPasswordMail(ctx context.Context, userId uuid.UUID, email string, code string, linkPattern string) {
	eventData := authlog.MailData{Kind: mailKindPasswordReset, UserID: userId.String()}
	authlog.Default.MailDeliveryStarted(ctx, eventData)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Password Reset",
	}
	mailValues := passwordResetValues{
		ResetLink: fmt.Sprintf(linkPattern, userId, code),
	}
	if err := payload.SetHtmlBody(assets.PasswordResetMailTmplFilePath, mailValues); err != nil {
		authlog.Default.MailTemplateRenderFailed(ctx, eventData, err)
	}
	s.sendMessage(ctx, payload, eventData)
}

func (s *Service) SendPasswordChangedMail(ctx context.Context, userId uuid.UUID, email string) {
	eventData := authlog.MailData{Kind: mailKindPasswordChanged, UserID: userId.String()}
	authlog.Default.MailDeliveryStarted(ctx, eventData)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Password Update",
	}
	if err := payload.SetHtmlBody(assets.PasswordChangedMailTmplFilePath, nil); err != nil {
		authlog.Default.MailTemplateRenderFailed(ctx, eventData, err)
	}
	s.sendMessage(ctx, payload, eventData)
}

func (s *Service) SendUsernameChangedMail(ctx context.Context, userId uuid.UUID, email, username string) {
	eventData := authlog.MailData{Kind: mailKindUsernameChanged, UserID: userId.String()}
	authlog.Default.MailDeliveryStarted(ctx, eventData)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Username Update",
	}
	mailValues := usernameChangedValue{
		Username: username,
	}
	if err := payload.SetHtmlBody(assets.UsernameChangedMailTmplFilePath, mailValues); err != nil {
		authlog.Default.MailTemplateRenderFailed(ctx, eventData, err)
	}
	s.sendMessage(ctx, payload, eventData)
}

func (s *Service) SendProfileDeletionRequestMail(ctx context.Context, userId uuid.UUID, email string, timestamp time.Time, withSharedData bool) {
	eventData := authlog.MailData{
		Kind:           mailKindProfileDeletionRequest,
		UserID:         userId.String(),
		WithSharedData: &withSharedData,
	}
	authlog.Default.MailDeliveryStarted(ctx, eventData)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Deletion Request",
	}
	mailValues := profileDeletionRequestValues{
		IncludeSharedData: "excluding",
		Timestamp:         timestamp.Format(time.RFC1123),
	}
	if withSharedData {
		mailValues.IncludeSharedData = "including"
	}

	if err := payload.SetHtmlBody(assets.ProfileDeletionRequestMailTmplFilePath, mailValues); err != nil {
		authlog.Default.MailTemplateRenderFailed(ctx, eventData, err)
	}
	s.sendMessage(ctx, payload, eventData)
}

func (s *Service) SendProfileDeletedMail(ctx context.Context, userId uuid.UUID, email string) {
	eventData := authlog.MailData{Kind: mailKindProfileDeleted, UserID: userId.String()}
	authlog.Default.MailDeliveryStarted(ctx, eventData)
	payload := mail.Payload{
		To:      email,
		Subject: "ChefBook Profile Deleted",
	}
	if err := payload.SetHtmlBody(assets.ProfileDeletedMailTmplFilePath, nil); err != nil {
		authlog.Default.MailTemplateRenderFailed(ctx, eventData, err)
	}
	s.sendMessage(ctx, payload, eventData)
}

func (s *Service) sendMessage(ctx context.Context, payload mail.Payload, eventData authlog.MailData) {
	if s.IsDevEnv {
		payload.Body = "DEV\n" + payload.Body
	}
	if err := s.sender.Send(payload, s.sendAttempts); err != nil {
		authlog.Default.MailDeliveryFailed(ctx, eventData, err)
	}
}
