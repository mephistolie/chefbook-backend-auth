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
	"github.com/mephistolie/chefbook-backend-auth/internal/service/reauthentication"
	"github.com/mephistolie/chefbook-backend-common/hash"
)

type Service struct {
	repo        repository.Data
	mq          repository.MessageQueue
	mail        *mail.Service
	hashManager hash.Manager
	reauth      *reauthentication.Service
}

func NewService(
	repo repository.Data,
	mq repository.MessageQueue,
	mailService *mail.Service,
	hashManager hash.Manager,
	reauth *reauthentication.Service,
) *Service {
	return &Service{
		repo:        repo,
		mq:          mq,
		mail:        mailService,
		hashManager: hashManager,
		reauth:      reauth,
	}
}

func (s *Service) GetInfo(ctx context.Context, userId uuid.UUID) (*time.Time, bool) {
	authInfo, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return nil, true
	}

	return authInfo.DeletionTimestamp, false
}

func (s *Service) Request(ctx context.Context, userId uuid.UUID, credentials entity.Reauthentication, deleteSharedData bool, redirect string) (entity.DeleteProfileRequest, error) {
	if err := s.reauth.Check(ctx, userId, credentials, redirect); err != nil {
		return entity.DeleteProfileRequest{}, err
	}
	info, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return entity.DeleteProfileRequest{}, err
	}
	if info.DeletionTimestamp != nil && !info.DeletionTimestamp.After(time.Now()) {
		return entity.DeleteProfileRequest{}, authFail.GrpcDeletionExpired
	}
	request, err := s.repo.RequestDeleteProfile(ctx, userId, deleteSharedData)
	if err != nil {
		return entity.DeleteProfileRequest{}, err
	}
	if info.DeletionTimestamp == nil {
		go s.mail.SendProfileDeletionRequestMail(context.WithoutCancel(ctx), userId, info.Email, request.Timestamp, request.WithSharedData)
	}
	return request, nil
}
func (s *Service) Update(ctx context.Context, userId uuid.UUID, deleteSharedData bool) (entity.DeleteProfileRequest, error) {
	info, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return entity.DeleteProfileRequest{}, err
	}
	if info.IsBlocked {
		return entity.DeleteProfileRequest{}, authFail.GrpcProfileIsBlocked
	}
	return s.repo.UpdateProfileDeletion(ctx, userId, deleteSharedData)
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
	if err == nil && msg != nil {
		s.mail.SendProfileDeletedMail(ctx, request.UserId, authInfo.Email)
		_ = s.mq.PublishProfilesMessage(ctx, msg)
	}

	return err
}

func (s *Service) Cancel(ctx context.Context, userId uuid.UUID) error {
	info, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return err
	}
	if info.IsBlocked {
		return authFail.GrpcProfileIsBlocked
	}
	return s.repo.CancelProfileDeletion(ctx, userId)
}
