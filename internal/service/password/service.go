package password

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	"github.com/mephistolie/chefbook-backend-common/hash"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

type Service struct {
	repo                 repository.Data
	mail                 mail.Service
	hashManager          hash.Manager
	resetPasswordCodeTTL time.Duration
}

func NewService(
	repo repository.Data,
	mailService mail.Service,
	hashManager hash.Manager,
	cfg config.Auth,
) *Service {
	return &Service{
		repo:                 repo,
		mail:                 mailService,
		hashManager:          hashManager,
		resetPasswordCodeTTL: *cfg.Ttl.PasswordResetCode,
	}
}

func (s *Service) RequestReset(ctx context.Context, email, username *string, resetLinkPattern string) error {
	authInfo, err := s.repo.GetAuthInfoByIdentifiers(ctx, entity.UserIdentifiers{Email: email, Username: username})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return err
	}
	if !authInfo.IsActivated || authInfo.IsBlocked || authInfo.DeletionTimestamp != nil {
		return nil
	}

	resetCode, err := s.repo.CreatePasswordResetRequest(ctx, authInfo.Id, time.Now().Add(s.resetPasswordCodeTTL))
	if err != nil {
		return err
	}

	go s.mail.SendResetPasswordMail(context.WithoutCancel(ctx), authInfo.Id, authInfo.Email, resetCode.String(), resetLinkPattern)

	return nil
}

func (s *Service) Reset(ctx context.Context, userId uuid.UUID, resetCode, newPassword string) error {
	if userId == uuid.Nil {
		var err error
		userId, err = s.repo.GetPasswordResetUser(ctx, resetCode)
		if err != nil {
			return err
		}
	}
	info, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return err
	}
	if info.IsBlocked {
		return authFail.GrpcProfileIsBlocked
	}
	if info.DeletionTimestamp != nil {
		return authFail.GrpcAccountDeleting
	}
	passwordHash, err := s.hashManager.Hash(newPassword)
	if err != nil {
		authlog.Default.PasswordHashFailed(ctx, err)
		return fail.GrpcUnknown
	}
	return s.repo.ResetPassword(ctx, userId, resetCode, passwordHash)
}

func (s *Service) Change(ctx context.Context, userId uuid.UUID, oldPassword, newPassword string) error {
	authInfo, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return authFail.GrpcUserNotFound
	}

	if authInfo.IsBlocked {
		return authFail.GrpcProfileIsBlocked
	}
	if authInfo.DeletionTimestamp != nil {
		return authFail.GrpcAccountDeleting
	}
	if s.hashManager.Validate(newPassword, authInfo.PasswordHash) == nil {
		return nil
	}
	if authInfo.PasswordHash == "" {
		return authFail.GrpcReauthentication
	}
	if len(authInfo.PasswordHash) > 0 {
		if err = s.hashManager.Validate(oldPassword, authInfo.PasswordHash); err != nil {
			authlog.Default.PasswordInvalid(ctx, userId.String())
			return authFail.GrpcReauthentication
		}
	}

	passwordHash, err := s.hashManager.Hash(newPassword)
	if err != nil {
		authlog.Default.PasswordHashFailed(ctx, err)
		return fail.GrpcUnknown
	}
	if err = s.repo.SetPassword(ctx, userId, passwordHash); err != nil {
		return err
	}

	go s.mail.SendPasswordChangedMail(context.WithoutCancel(ctx), userId, authInfo.Email)

	return nil
}
