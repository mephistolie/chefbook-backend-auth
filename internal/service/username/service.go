package username

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
	return s.repo.GetUsernames(ctx, userIds)
}

func (s *Service) CheckAvailability(ctx context.Context, username string) (bool, error) {
	if _, err := s.repo.GetAuthInfoByUsername(ctx, username); err == nil {
		return false, nil
	}
	return true, nil
}

func (s *Service) Set(ctx context.Context, userId uuid.UUID, username string) error {
	email, err := s.repo.SetUsername(ctx, userId, username)
	if err == nil {
		go s.mail.SendUsernameChangedMail(context.WithoutCancel(ctx), userId, email, username)
	}
	return err
}
