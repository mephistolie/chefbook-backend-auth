package nickname

import (
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

func (s *Service) CheckAvailability(nickname string) (bool, error) {
	if _, err := s.repo.GetAuthInfoByNickname(nickname); err == nil {
		return false, nil
	}
	return true, nil
}

func (s *Service) Set(userId uuid.UUID, nickname string) error {
	email, err := s.repo.SetNickname(userId, nickname)
	if err == nil {
		go s.mail.SendNicknameChangedMail(email, nickname)
	}
	return err
}
