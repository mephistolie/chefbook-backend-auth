package oauth

import (
	"context"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/vk"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

const VkScope = 1 << 22

type Service struct {
	repo      repository.Data
	providers oauth.Providers
}

func NewService(repo repository.Data, providers oauth.Providers) *Service {
	return &Service{
		repo:      repo,
		providers: providers,
	}
}

func (s *Service) GenerateGoogleLink(redirectUrl string) string {
	return s.providers.Google.CreateOAuthLink(redirectUrl)
}

func (s *Service) ConnectGoogle(ctx context.Context, userId uuid.UUID, code string, state, redirectUrl string) error {
	googleInfo, err := s.providers.Google.GetUserInfoByCode(ctx, code, state, redirectUrl)
	if err != nil {
		log.AutoWarnf("invalid google oauth for user %s: %s", code, err)
		return authFail.GrpcInvalidCode
	}

	return s.repo.ConnectGoogle(ctx, userId, googleInfo.UserId)
}

func (s *Service) DeleteGoogleConnection(ctx context.Context, userId uuid.UUID) error {
	authInfo, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return err
	}
	if authInfo.OAuth.VkId == nil {
		return nil
	}
	if !s.hasMultipleSignInMethods(authInfo) {
		return authFail.GrpcFewSignInMethods
	}
	return s.repo.DeleteGoogleConnection(ctx, userId)
}

func (s *Service) GenerateVkLink(display, responseType, redirectUri string) (string, error) {
	params := vk.OAuthParams{
		Display:      display,
		ResponseType: responseType,
		RedirectUri:  redirectUri,
	}
	link, err := s.providers.Vk.CreateOAuthLink(params)
	if err != nil {
		return "", fail.GrpcUnknown
	}
	return link, nil
}

func (s *Service) ConnectVk(ctx context.Context, userId uuid.UUID, code, state string, redirectUri string) error {
	vkResponse, err := s.providers.Vk.GetAccessToken(ctx, code, state, redirectUri)
	if err != nil {
		log.AutoWarnf("invalid vk oauth for user %s: %s", code, err)
		return authFail.GrpcInvalidCode
	}

	return s.repo.ConnectVk(ctx, userId, vkResponse.UserId)
}

func (s *Service) DeleteVkConnection(ctx context.Context, userId uuid.UUID) error {
	authInfo, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return err
	}
	if authInfo.OAuth.VkId == nil {
		return nil
	}
	if !s.hasMultipleSignInMethods(authInfo) {
		return authFail.GrpcFewSignInMethods
	}
	return s.repo.DeleteVkConnection(ctx, userId)
}

func (s *Service) hasMultipleSignInMethods(authInfo entity.AuthInfo) bool {
	count := 0
	increaseForCondition(&count, len(authInfo.PasswordHash) > 0)
	increaseForCondition(&count, authInfo.OAuth.GoogleId != nil)
	increaseForCondition(&count, authInfo.OAuth.VkId != nil)
	return count > 1
}

func increaseForCondition(val *int, condition bool) {
	if condition {
		*val += 1
	}
}
