package profile_deletion

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	"github.com/mephistolie/chefbook-backend-common/hash"
)

type Service struct {
	repo        repository.Data
	mq          repository.MessageQueue
	mail        *mail.Service
	hashManager hash.Manager
}

func NewService(
	repo repository.Data,
	mq repository.MessageQueue,
	mailService *mail.Service,
	hashManager hash.Manager,
) *Service {
	return &Service{
		repo:        repo,
		mq:          mq,
		mail:        mailService,
		hashManager: hashManager,
	}
}

func (s *Service) GetInfo(ctx context.Context, userId uuid.UUID) (*time.Time, bool) {
	authInfo, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return nil, true
	}

	return authInfo.DeletionTimestamp, false
}

func (s *Service) Request(ctx context.Context, userId uuid.UUID, password string, deleteSharedData bool) (time.Time, error) {
	authInfo, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return time.Time{}, authFail.GrpcUserNotFound
	}

	if err = s.hashManager.Validate(password, authInfo.PasswordHash); err != nil {
		authlog.Default.PasswordInvalid(ctx, userId.String())
		return time.Time{}, authFail.GrpcInvalidPassword
	}

	timestamp, err := s.repo.RequestDeleteProfile(ctx, userId, deleteSharedData)
	if err != nil {
		return time.Time{}, err
	} else {
		go s.mail.SendProfileDeletionRequestMail(context.WithoutCancel(ctx), userId, authInfo.Email, timestamp, deleteSharedData)
	}

	return timestamp, nil
}

func (s *Service) ExecuteAll() {
	ctx := context.Background()
	requests := s.repo.GetProfilesToDelete(ctx)
	for _, request := range requests {
		_ = s.Execute(ctx, request)
	}
}

func (s *Service) Execute(ctx context.Context, request entity.DeleteProfileRequest) error {
	authInfo, err := s.repo.GetAuthInfoById(ctx, request.UserId)
	if err != nil {
		authlog.Default.ProfileDeletionTargetMissing(ctx, request.UserId.String())
		return authFail.GrpcUserNotFound
	}

	msg, err := s.repo.DeleteUser(ctx, request.UserId, request.WithSharedData)
	if err == nil {
		s.mail.SendProfileDeletedMail(ctx, request.UserId, authInfo.Email)
		_ = s.mq.PublishProfilesMessage(ctx, msg)
	}

	return err
}

func (s *Service) Cancel(ctx context.Context, userId uuid.UUID) error {
	return s.repo.CancelProfileDeletion(ctx, userId)
}
