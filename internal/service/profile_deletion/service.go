package profile_deletion

import (
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	"github.com/mephistolie/chefbook-backend-common/hash"
	"github.com/mephistolie/chefbook-backend-common/log"
	"time"
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

func (s *Service) GetInfo(userId uuid.UUID) (*time.Time, bool) {
	authInfo, err := s.repo.GetAuthInfoById(userId)
	if err != nil {
		return nil, true
	}

	return authInfo.DeletionTimestamp, false
}

func (s *Service) Request(userId uuid.UUID, password string, deleteSharedData bool) (time.Time, error) {
	authInfo, err := s.repo.GetAuthInfoById(userId)
	if err != nil {
		return time.Time{}, authFail.GrpcUserNotFound
	}

	if err = s.hashManager.Validate(password, authInfo.PasswordHash); err != nil {
		log.Infof("invalid password for user %s: %s", userId, err)
		return time.Time{}, authFail.GrpcInvalidPassword
	}

	timestamp, err := s.repo.RequestDeleteProfile(userId, deleteSharedData)
	if err != nil {
		return time.Time{}, err
	} else {
		go s.mail.SendProfileDeletionRequestMail(authInfo.Email, timestamp, deleteSharedData)
	}

	return timestamp, nil
}

func (s *Service) ExecuteAll() {
	requests := s.repo.GetProfilesToDelete()
	for _, request := range requests {
		_ = s.Execute(request)
	}
}

func (s *Service) Execute(request entity.DeleteProfileRequest) error {
	authInfo, err := s.repo.GetAuthInfoById(request.UserId)
	if err != nil {
		log.Warnf("profile %s to delete not found: %s", request.UserId, err)
		return authFail.GrpcUserNotFound
	}

	msg, err := s.repo.DeleteUser(request.UserId, request.WithSharedData)
	if err == nil {
		s.mail.SendProfileDeletedMail(authInfo.Email)
		_ = s.mq.PublishProfilesMessage(msg)
	}

	return err
}

func (s *Service) Cancel(userId uuid.UUID) error {
	return s.repo.CancelProfileDeletion(userId)
}
