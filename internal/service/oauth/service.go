package oauth

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/vk"
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

func (s *Service) GenerateGoogleLink(ctx context.Context, redirectUrl string) (string, error) {
	return s.providers.Google.CreateOAuthLink(ctx, redirectUrl)
}

func (s *Service) ConnectGoogle(ctx context.Context, userId uuid.UUID, code string, state, redirectUrl string) (bool, error) {
	googleInfo, err := s.providers.Google.GetUserInfoByCode(ctx, code, state, redirectUrl)
	if err != nil {
		authlog.Default.OAuthCodeRejected(ctx, authlog.OAuthData{
			Provider: "google",
			UserID:   userId.String(),
		}, err)
		if status.Code(err) == codes.Internal || status.Code(err) == codes.Unavailable {
			return false, err
		}
		return false, authFail.GrpcInvalidCode
	}

	return s.repo.ConnectGoogle(ctx, userId, googleInfo.UserId)
}

func (s *Service) DeleteGoogleConnection(ctx context.Context, userId uuid.UUID) error {
	authInfo, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return err
	}
	if authInfo.IsBlocked {
		return authFail.GrpcProfileIsBlocked
	}
	if authInfo.DeletionTimestamp != nil {
		return authFail.GrpcAccountDeleting
	}
	if authInfo.OAuth.GoogleId == nil {
		return nil
	}
	if !s.hasMultipleSignInMethods(authInfo) {
		return authFail.GrpcFewSignInMethods
	}
	return s.repo.DeleteGoogleConnection(ctx, userId)
}

func (s *Service) GenerateVkLink(ctx context.Context, display, responseType, redirectUrl string) (string, error) {
	params := vk.OAuthParams{
		Display:      display,
		ResponseType: responseType,
		RedirectUri:  redirectUrl,
	}
	link, err := s.providers.Vk.CreateOAuthLink(ctx, params)
	if err != nil {
		return "", fail.GrpcUnknown
	}
	return link, nil
}

func (s *Service) ConnectVk(ctx context.Context, userId uuid.UUID, code, state string, redirectUri string) (bool, error) {
	vkResponse, err := s.providers.Vk.GetAccessToken(ctx, code, state, redirectUri)
	if err != nil {
		authlog.Default.OAuthCodeRejected(ctx, authlog.OAuthData{
			Provider: "vk",
			UserID:   userId.String(),
		}, err)
		if status.Code(err) == codes.Internal || status.Code(err) == codes.Unavailable {
			return false, err
		}
		return false, authFail.GrpcInvalidCode
	}

	return s.repo.ConnectVk(ctx, userId, vkResponse.UserId)
}

func (s *Service) DeleteVkConnection(ctx context.Context, userId uuid.UUID) error {
	authInfo, err := s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return err
	}
	if authInfo.IsBlocked {
		return authFail.GrpcProfileIsBlocked
	}
	if authInfo.DeletionTimestamp != nil {
		return authFail.GrpcAccountDeleting
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

func (s *Service) ConnectGoogleToken(ctx context.Context, id uuid.UUID, token string) (bool, error) {
	info, err := s.providers.Google.GetUserInfoByIdToken(ctx, token)
	if err != nil {
		if status.Code(err) == codes.Internal || status.Code(err) == codes.Unavailable {
			return false, err
		}
		return false, authFail.GrpcInvalidCode
	}
	return s.repo.ConnectGoogle(ctx, id, info.UserId)
}
