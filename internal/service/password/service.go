package password

import (
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	"github.com/mephistolie/chefbook-backend-common/hash"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

type Service struct {
	repo                 repository.Auth
	mail                 mail.Service
	hashManager          hash.Manager
	resetPasswordCodeTTL time.Duration
}

func NewService(
	repo repository.Auth,
	mailService mail.Service,
	hashManager hash.Manager,
	cfg config.Auth,
) *Service {
	return &Service{
		repo:                 repo,
		mail:                 mailService,
		hashManager:          hashManager,
		resetPasswordCodeTTL: *cfg.Ttl.ResetPasswordCode,
	}
}

func (s *Service) RequestReset(email, nickname *string) error {
	authInfo, err := s.repo.GetAuthInfoByIdentifiers(entity.UserIdentifiers{Email: email, Nickname: nickname})
	if err != nil {
		return nil
	}

	resetCode, err := s.repo.CreatePasswordResetRequest(authInfo.Id, time.Now().Add(s.resetPasswordCodeTTL))
	if err != nil {
		return err
	}

	go s.mail.SendResetPasswordMail(authInfo.Id, authInfo.Email, resetCode.String())

	return nil
}

func (s *Service) Reset(userId uuid.UUID, resetCode, newPassword string) error {
	passwordHash, err := s.hashManager.Hash(newPassword)
	if err != nil {
		log.Errorf("unable to hash password: %s", err)
		return fail.GrpcUnknown
	}
	return s.repo.ResetPassword(userId, resetCode, passwordHash)
}

func (s *Service) Change(userId uuid.UUID, oldPassword, newPassword string) error {
	authInfo, err := s.repo.GetAuthInfoById(userId)
	if err != nil {
		return authFail.GrpcUserNotFound
	}

	if err = s.hashManager.Validate(oldPassword, authInfo.PasswordHash); err != nil {
		log.Infof("invalid password for user %s: %s", userId, err)
		return authFail.GrpcInvalidPassword
	}

	passwordHash, err := s.hashManager.Hash(newPassword)
	if err != nil {
		log.Errorf("unable to hash password: %s", err)
		return fail.GrpcUnknown
	}
	if err = s.repo.SetPassword(userId, passwordHash); err != nil {
		return err
	}

	go s.mail.SendPasswordChangedMail(authInfo.Email)

	return nil
}
