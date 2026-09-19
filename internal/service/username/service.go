package username

import (
	"context"
	"github.com/google/uuid"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	} else if status.Code(err) != codes.NotFound {
		return false, err
	}
	return true, nil
}

func (s *Service) Set(ctx context.Context, userId uuid.UUID, username string) error {
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
	if info.Username != nil && *info.Username == username {
		return nil
	}
	email, err := s.repo.SetUsername(ctx, userId, username)
	if err == nil {
		go s.mail.SendUsernameChangedMail(context.WithoutCancel(ctx), userId, email, username)
	}
	return err
}
