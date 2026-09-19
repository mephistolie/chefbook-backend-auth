package email

import (
	"context"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/mail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/reauthentication"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
	"time"
)

type Service struct {
	repo   repository.Data
	reauth *reauthentication.Service
	mail   *mail.Service
}

func New(repo repository.Data, reauth *reauthentication.Service, mail *mail.Service) *Service {
	return &Service{repo, reauth, mail}
}
func (s *Service) Verify(ctx context.Context, address, pattern string, passwordHash *string) error {
	info, err := s.repo.GetAuthInfoByEmail(ctx, address)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return err
	}
	if info.IsActivated || info.IsBlocked {
		return nil
	}
	return s.repo.StartEmailBinding(ctx, entity.EmailBinding{UserId: info.Id, Purpose: "verify", Stage: "verify", OldEmail: info.Email, Email: info.Email, LinkPattern: pattern, PasswordHash: passwordHash, ExpiresAt: time.Now().Add(24 * time.Hour)})
}
func (s *Service) Change(ctx context.Context, id uuid.UUID, address, pattern, redirect string, credentials entity.Reauthentication) error {
	if err := s.reauth.Check(ctx, id, credentials, redirect); err != nil {
		return err
	}
	info, err := s.repo.GetAuthInfoById(ctx, id)
	if err != nil {
		return err
	}
	if info.DeletionTimestamp != nil {
		return authFail.GrpcAccountDeleting
	}
	if strings.EqualFold(info.Email, address) {
		return fail.CreateGrpcConflict("email_unchanged", "email already assigned to account")
	}
	return s.repo.StartEmailBinding(ctx, entity.EmailBinding{UserId: id, Purpose: "change", Stage: "old", OldEmail: info.Email, Email: address, LinkPattern: pattern, ExpiresAt: time.Now().Add(24 * time.Hour)})
}
func (s *Service) Confirm(ctx context.Context, token, pattern string) (entity.EmailConfirmation, error) {
	return s.repo.ConfirmEmailBinding(ctx, token, pattern)
}
func (s *Service) Dispatch(ctx context.Context) {
	if s.repo.CleanupAuthWorkflows(ctx) != nil {
		return
	}
	for i := 0; i < 25; i++ {
		ok, err := s.repo.DeliverEmail(ctx, s.mail.SendEmailBinding)
		if err != nil || !ok {
			return
		}
	}
}
