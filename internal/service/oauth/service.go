package oauth

import (
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
	repo      repository.Auth
	providers oauth.Providers
}

func NewService(repo repository.Auth, providers oauth.Providers) *Service {
	return &Service{
		repo:      repo,
		providers: providers,
	}
}

func (s *Service) GenerateGoogleLink(redirectUrl string) string {
	return s.providers.Google.CreateOAuthLink(redirectUrl)
}

func (s *Service) ConnectGoogle(userId uuid.UUID, code string, state, redirectUrl string) error {
	googleInfo, err := s.providers.Google.GetUserInfoByCode(code, state, redirectUrl)
	if err != nil {
		log.Warnf("invalid google oauth for user %s: ", code, err)
		return authFail.GrpcInvalidCode
	}

	return s.repo.ConnectGoogle(userId, googleInfo.UserId)
}

func (s *Service) DeleteGoogleConnection(userId uuid.UUID) error {
	authInfo, err := s.repo.GetAuthInfoById(userId)
	if err != nil {
		return err
	}
	if s.getSignInMethodsCount(authInfo) <= 1 {
		return authFail.GrpcFewSignInMethods
	}
	return s.repo.DeleteGoogleConnection(userId)
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

func (s *Service) ConnectVk(userId uuid.UUID, code, state string, redirectUri string) error {
	vkResponse, err := s.providers.Vk.GetAccessToken(code, state, redirectUri)
	if err != nil {
		log.Warnf("invalid google oauth for user %s: ", code, err)
		return authFail.GrpcInvalidCode
	}

	return s.repo.ConnectVk(userId, vkResponse.UserId)
}

func (s *Service) DeleteVkConnection(userId uuid.UUID) error {
	authInfo, err := s.repo.GetAuthInfoById(userId)
	if err != nil {
		return err
	}
	if s.getSignInMethodsCount(authInfo) <= 1 {
		return authFail.GrpcFewSignInMethods
	}
	return s.repo.DeleteVkConnection(userId)
}

func (s *Service) getSignInMethodsCount(authInfo entity.AuthInfo) int {
	count := 0
	increaseForCondition(&count, len(authInfo.PasswordHash) > 0)
	increaseForCondition(&count, authInfo.OAuth.GoogleId != nil)
	increaseForCondition(&count, authInfo.OAuth.VkId != nil)
	return count
}

func increaseForCondition(val *int, condition bool) {
	if condition {
		*val += 1
	}
}
