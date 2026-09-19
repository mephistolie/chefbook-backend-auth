package session

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/google"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/vk"
)

func (s *Service) SignInGoogle(ctx context.Context, credentials entity.OAuthCredentials, client entity.ClientData, redirectUrl string) (entity.Tokens, error) {
	googleInfo, err := s.oauthProviders.Google.GetUserInfoByCode(ctx, credentials.Code, credentials.State, redirectUrl)
	if err != nil {
		if status.Code(err) == codes.Internal || status.Code(err) == codes.Unavailable {
			return entity.Tokens{}, err
		}
		return entity.Tokens{}, authFail.GrpcInvalidCode
	}

	return s.handleGoogleInfoResponse(ctx, googleInfo, client)
}

func (s *Service) SignInGoogleIdToken(ctx context.Context, token string, client entity.ClientData) (entity.Tokens, error) {
	googleInfo, err := s.oauthProviders.Google.GetUserInfoByIdToken(ctx, token)
	if err != nil {
		if status.Code(err) == codes.Internal || status.Code(err) == codes.Unavailable {
			return entity.Tokens{}, err
		}
		return entity.Tokens{}, authFail.GrpcInvalidCode
	}

	return s.handleGoogleInfoResponse(ctx, googleInfo, client)
}

func (s *Service) handleGoogleInfoResponse(ctx context.Context, googleInfo *google.UserInfoResponse, client entity.ClientData) (entity.Tokens, error) {
	var authInfo entity.AuthInfo
	authInfo, err := s.repo.GetAuthInfoByGoogleId(ctx, googleInfo.UserId)
	if err != nil && status.Code(err) != codes.NotFound {
		return entity.Tokens{}, err
	}
	if err != nil && len(googleInfo.Email) > 0 {
		authInfo, err = s.repo.GetAuthInfoByEmail(ctx, googleInfo.Email)
	}

	if err != nil && status.Code(err) != codes.NotFound {
		return entity.Tokens{}, err
	}
	if err == nil {
		return s.signInGoogleWithExistingProfile(ctx, authInfo, *googleInfo, client)
	} else {
		return s.signInGoogleWithProfileCreation(ctx, authInfo, *googleInfo, client)
	}
}

func (s *Service) signInGoogleWithExistingProfile(
	ctx context.Context,
	authInfo entity.AuthInfo,
	googleInfo google.UserInfoResponse,
	client entity.ClientData,
) (entity.Tokens, error) {
	if err := s.checkProfileAvailability(ctx, authInfo); err != nil {
		return entity.Tokens{}, err
	}
	if authInfo.OAuth.GoogleId == nil && authInfo.DeletionTimestamp != nil {
		return entity.Tokens{}, authFail.GrpcInvalidCredentials
	}
	if authInfo.OAuth.GoogleId == nil || *authInfo.OAuth.GoogleId != googleInfo.UserId {
		if _, err := s.repo.ConnectGoogle(ctx, authInfo.Id, googleInfo.UserId); err != nil {
			if status.Code(err) == codes.FailedPrecondition {
				return entity.Tokens{}, authFail.GrpcInvalidCredentials
			}
			return entity.Tokens{}, err
		}
	}
	if err := s.checkProfileAvailability(ctx, authInfo); err != nil {
		return entity.Tokens{}, err
	}
	return s.createSession(ctx, authInfo, client)
}

func (s *Service) signInGoogleWithProfileCreation(
	ctx context.Context,
	authInfo entity.AuthInfo,
	googleInfo google.UserInfoResponse,
	client entity.ClientData,
) (entity.Tokens, error) {
	if len(googleInfo.Email) == 0 {
		return entity.Tokens{}, authFail.GrpcEmailRequired
	}

	credentials := entity.CredentialsHash{Email: googleInfo.Email}
	userId, msg, err := s.repo.CreateUser(ctx, credentials, nil, entity.OAuth{GoogleId: &googleInfo.UserId})
	if err != nil {
		return entity.Tokens{}, err
	}
	go s.mq.PublishProfilesMessage(context.WithoutCancel(ctx), msg)

	authInfo, err = s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return entity.Tokens{}, err
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if connectErr := s.connectFirebaseProfile(ctx, authInfo.Id, authInfo.Email); connectErr != nil {
			authlog.Default.FirebaseProfileConnectFailed(ctx, authInfo.Id.String(), connectErr)
		}
	}()

	return s.createSession(ctx, authInfo, client)
}

func (s *Service) SignInVk(ctx context.Context, credentials entity.OAuthCredentials, client entity.ClientData, redirectUri string) (entity.Tokens, error) {
	vkInfo, err := s.oauthProviders.Vk.GetAccessToken(ctx, credentials.Code, credentials.State, redirectUri)
	if err != nil {
		if status.Code(err) == codes.Internal || status.Code(err) == codes.Unavailable {
			return entity.Tokens{}, err
		}
		return entity.Tokens{}, authFail.GrpcInvalidCode
	}

	var authInfo entity.AuthInfo
	authInfo, err = s.repo.GetAuthInfoByVkId(ctx, vkInfo.UserId)
	if err != nil && status.Code(err) != codes.NotFound {
		return entity.Tokens{}, err
	}
	if err != nil && len(vkInfo.Email) > 0 {
		authInfo, err = s.repo.GetAuthInfoByEmail(ctx, vkInfo.Email)
	}

	if err != nil && status.Code(err) != codes.NotFound {
		return entity.Tokens{}, err
	}
	if err == nil {
		return s.signInVkWithExistingProfile(ctx, authInfo, *vkInfo, client)
	} else {
		return s.signInVkWithProfileCreation(ctx, authInfo, *vkInfo, client)
	}
}

func (s *Service) signInVkWithExistingProfile(
	ctx context.Context,
	authInfo entity.AuthInfo,
	vkInfo vk.AccessTokenResponse,
	client entity.ClientData,
) (entity.Tokens, error) {
	if err := s.checkProfileAvailability(ctx, authInfo); err != nil {
		return entity.Tokens{}, err
	}
	if authInfo.OAuth.VkId == nil && authInfo.DeletionTimestamp != nil {
		return entity.Tokens{}, authFail.GrpcInvalidCredentials
	}
	if authInfo.OAuth.VkId == nil || *authInfo.OAuth.VkId != vkInfo.UserId {
		if _, err := s.repo.ConnectVk(ctx, authInfo.Id, vkInfo.UserId); err != nil {
			if status.Code(err) == codes.FailedPrecondition {
				return entity.Tokens{}, authFail.GrpcInvalidCredentials
			}
			return entity.Tokens{}, err
		}
	}
	if err := s.checkProfileAvailability(ctx, authInfo); err != nil {
		return entity.Tokens{}, err
	}
	return s.createSession(ctx, authInfo, client)
}

func (s *Service) signInVkWithProfileCreation(
	ctx context.Context,
	authInfo entity.AuthInfo,
	vkInfo vk.AccessTokenResponse,
	client entity.ClientData,
) (entity.Tokens, error) {
	if len(vkInfo.Email) == 0 {
		return entity.Tokens{}, authFail.GrpcEmailRequired
	}

	credentials := entity.CredentialsHash{Email: vkInfo.Email}
	userId, msg, err := s.repo.CreateUser(ctx, credentials, nil, entity.OAuth{VkId: &vkInfo.UserId})
	if err != nil {
		return entity.Tokens{}, err
	}
	go s.mq.PublishProfilesMessage(context.WithoutCancel(ctx), msg)

	authInfo, err = s.repo.GetAuthInfoById(ctx, userId)
	if err != nil {
		return entity.Tokens{}, err
	}

	go func() {
		ctx := context.WithoutCancel(ctx)
		if connectErr := s.connectFirebaseProfile(ctx, authInfo.Id, authInfo.Email); connectErr != nil {
			authlog.Default.FirebaseProfileConnectFailed(ctx, authInfo.Id.String(), connectErr)
		}
	}()

	return s.createSession(ctx, authInfo, client)
}
