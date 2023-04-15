package session

import (
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/google"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/vk"
)

func (s *Service) SignInGoogle(credentials entity.OAuthCredentials, client entity.ClientData) (entity.Tokens, error) {
	googleInfo, err := s.oauthProviders.Google.GetUserInfoByCode(credentials.Code, credentials.State)
	if err != nil {
		return entity.Tokens{}, authFail.GrpcInvalidCode
	}

	var authInfo entity.AuthInfo
	authInfo, err = s.repo.GetAuthInfoByGoogleId(googleInfo.UserId)
	if err != nil && len(googleInfo.Email) > 0 {
		authInfo, err = s.repo.GetAuthInfoByEmail(googleInfo.Email)
	}

	if err == nil {
		return s.signInGoogleWithExistingProfile(authInfo, *googleInfo, client)
	} else {
		return s.signInGoogleWithProfileCreation(authInfo, *googleInfo, client)
	}
}

func (s *Service) signInGoogleWithExistingProfile(
	authInfo entity.AuthInfo,
	googleInfo google.UserInfoResponse,
	client entity.ClientData,
) (entity.Tokens, error) {
	if authInfo.OAuth.GoogleId == nil || *authInfo.OAuth.GoogleId != googleInfo.UserId {
		if err := s.repo.ConnectGoogle(authInfo.Id, googleInfo.UserId); err != nil {
			return entity.Tokens{}, err
		}
	}
	if err := s.checkProfileAvailability(authInfo); err != nil {
		return entity.Tokens{}, err
	}
	return s.createSession(authInfo, client)
}

func (s *Service) signInGoogleWithProfileCreation(
	authInfo entity.AuthInfo,
	googleInfo google.UserInfoResponse,
	client entity.ClientData,
) (entity.Tokens, error) {
	if len(googleInfo.Email) == 0 {
		return entity.Tokens{}, authFail.GrpcEmailRequired
	}
	credentials := entity.CredentialsHash{Email: googleInfo.Email}
	userId, err := s.repo.CreateUser(credentials, nil, entity.OAuth{GoogleId: &googleInfo.UserId})
	if err != nil {
		return entity.Tokens{}, err
	}
	authInfo, err = s.repo.GetAuthInfoById(userId)
	if err != nil {
		return entity.Tokens{}, err
	}
	return s.createSession(authInfo, client)
}

func (s *Service) SignInVk(credentials entity.OAuthCredentials, client entity.ClientData) (entity.Tokens, error) {
	vkInfo, err := s.oauthProviders.Vk.GetAccessToken(credentials.Code, credentials.State)
	if err != nil {
		return entity.Tokens{}, authFail.GrpcInvalidCode
	}

	var authInfo entity.AuthInfo
	authInfo, err = s.repo.GetAuthInfoByVkId(vkInfo.UserId)
	if err != nil && len(vkInfo.Email) > 0 {
		authInfo, err = s.repo.GetAuthInfoByEmail(vkInfo.Email)
	}

	if err == nil {
		return s.signInVkWithExistingProfile(authInfo, *vkInfo, client)
	} else {
		return s.signInVkWithProfileCreation(authInfo, *vkInfo, client)
	}
}

func (s *Service) signInVkWithExistingProfile(
	authInfo entity.AuthInfo,
	vkInfo vk.AccessTokenResponse,
	client entity.ClientData,
) (entity.Tokens, error) {
	if authInfo.OAuth.VkId == nil || *authInfo.OAuth.VkId != vkInfo.UserId {
		if err := s.repo.ConnectVk(authInfo.Id, vkInfo.UserId); err != nil {
			return entity.Tokens{}, err
		}
	}
	if err := s.checkProfileAvailability(authInfo); err != nil {
		return entity.Tokens{}, err
	}
	return s.createSession(authInfo, client)
}

func (s *Service) signInVkWithProfileCreation(
	authInfo entity.AuthInfo,
	vkInfo vk.AccessTokenResponse,
	client entity.ClientData,
) (entity.Tokens, error) {
	if len(vkInfo.Email) == 0 {
		return entity.Tokens{}, authFail.GrpcEmailRequired
	}
	credentials := entity.CredentialsHash{Email: vkInfo.Email}
	userId, err := s.repo.CreateUser(credentials, nil, entity.OAuth{VkId: &vkInfo.UserId})
	if err != nil {
		return entity.Tokens{}, err
	}
	authInfo, err = s.repo.GetAuthInfoById(userId)
	if err != nil {
		return entity.Tokens{}, err
	}
	return s.createSession(authInfo, client)
}
