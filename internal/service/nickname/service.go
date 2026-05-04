package nickname

import (
	"context"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
)

type Service struct {
	repo repository.Data
	mail mail.Service
}

func NewService(repo repository.Data, mailService mail.Service) *Service {
	return &Service{
		repo: repo,
		mail: mailService,
	}
}

func (s *Service) Get(ctx context.Context, userIds []uuid.UUID) (map[uuid.UUID]string, error) {
	return s.repo.GetNicknames(ctx, userIds)
}

func (s *Service) CheckAvailability(ctx context.Context, nickname string) (bool, error) {
	if _, err := s.repo.GetAuthInfoByNickname(ctx, nickname); err == nil {
		return false, nil
	}
	return true, nil
}

func (s *Service) Set(ctx context.Context, userId uuid.UUID, nickname string) error {
	email, err := s.repo.SetNickname(ctx, userId, nickname)
	if err == nil {
		go s.mail.SendNicknameChangedMail(email, nickname)
	}
	return err
}
