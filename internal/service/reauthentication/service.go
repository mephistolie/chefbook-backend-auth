package reauthentication

import (
	"context"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth"
	"github.com/mephistolie/chefbook-backend-common/hash"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

type Service struct {
	repo      repository.Data
	providers oauth.Providers
	hash      hash.Manager
}

func New(repo repository.Data, providers oauth.Providers, hash hash.Manager) *Service {
	return &Service{repo, providers, hash}
}
func (s *Service) Check(ctx context.Context, id uuid.UUID, c entity.Reauthentication, redirect string) error {
	info, err := s.repo.GetAuthInfoById(ctx, id)
	if err != nil {
		return err
	}
	if info.IsBlocked {
		return authFail.GrpcProfileIsBlocked
	}
	switch c.Method {
	case "password":
		if c.Password != "" && c.IdToken == "" && c.Code == "" && c.State == "" && s.hash.Validate(c.Password, info.PasswordHash) == nil {
			return nil
		}
	case "google":
		if c.IdToken == "" || c.Password != "" || c.Code != "" || c.State != "" {
			break
		}
		p, err := s.providers.Google.GetUserInfoByIdToken(ctx, c.IdToken)
		if err != nil && (status.Code(err) == codes.Internal || status.Code(err) == codes.Unavailable) {
			return err
		}
		if err == nil && info.OAuth.GoogleId != nil && p.UserId == *info.OAuth.GoogleId {
			if !freshAuthentication(p.AuthenticatedAt, time.Now()) {
				return authFail.GrpcReauthentication
			}
			return s.repo.ConsumeReauthentication(ctx, id, c.IdToken)
		}
	case "vk":
		if c.Code == "" || c.State == "" || c.Password != "" || c.IdToken != "" {
			break
		}
		p, err := s.providers.Vk.GetAccessToken(ctx, c.Code, c.State, redirect)
		if err != nil && (status.Code(err) == codes.Internal || status.Code(err) == codes.Unavailable) {
			return err
		}
		if err == nil && info.OAuth.VkId != nil && p.UserId == *info.OAuth.VkId {
			return nil
		}
	}
	return authFail.GrpcReauthentication
}

func freshAuthentication(timestamp int64, now time.Time) bool {
	return timestamp > 0 && timestamp <= now.Unix()+30 && now.Unix()-timestamp <= 300
}
