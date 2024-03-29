package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/grpc/dto"
	credentialUtils "github.com/mephistolie/chefbook-backend-auth/internal/transport/utils/credentials"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *AuthServer) SignUp(_ context.Context, req *api.SignUpRequest) (*api.SignUpResponse, error) {
	var requestedIdPtr *uuid.UUID = nil
	requestedId, err := uuid.Parse(req.Id)
	if err == nil {
		requestedIdPtr = &requestedId
	}
	if err := credentialUtils.ValidateEmail(req.Email); err != nil {
		return nil, err
	}
	if err := credentialUtils.ValidatePassword(req.Password); err != nil {
		return nil, err
	}
	credentials := entity.SignUpCredentials{
		Id:       requestedIdPtr,
		Email:    req.Email,
		Password: req.Password,
	}
	id, activated, err := s.service.Session.SignUp(credentials, req.ActivationLinkPattern)
	if err != nil {
		return nil, err
	}
	return &api.SignUpResponse{Id: id.String(), Activated: activated}, nil
}

func (s *AuthServer) ActivateProfile(_ context.Context, req *api.ActivateProfileRequest) (*api.ActivateProfileResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}
	if err = s.service.Session.ActivateProfile(id, req.ActivationCode); err != nil {
		return nil, err
	}
	return &api.ActivateProfileResponse{Message: "profile activated"}, nil
}

func (s *AuthServer) SignIn(_ context.Context, req *api.SignInRequest) (*api.SessionResponse, error) {
	if len(req.Email) == 0 && len(req.Nickname) == 0 {
		return nil, fail.GrpcInvalidBody
	}
	credentials := entity.SignInCredentials{
		Password: req.Password,
	}
	if len(req.Email) > 0 {
		credentials.Email = &req.Email
	}
	if len(req.Nickname) > 0 {
		credentials.Nickname = &req.Nickname
	}

	tokens, err := s.service.Session.SignIn(credentials, entity.ClientData{Ip: req.Ip, UserAgent: req.UserAgent})
	if err != nil {
		return nil, err
	}

	return dto.NewSessionResponse(tokens), nil
}

func (s *AuthServer) GetAccessTokenPublicKey(_ context.Context, _ *api.GetAccessTokenPublicKeyRequest) (*api.GetAccessTokenPublicKeyResponse, error) {
	return &api.GetAccessTokenPublicKeyResponse{PublicKey: s.service.Session.GetAccessTokenPublicKey()}, nil
}

func (s *AuthServer) RefreshSession(_ context.Context, req *api.RefreshSessionRequest) (*api.SessionResponse, error) {
	tokens, err := s.service.Session.Refresh(req.RefreshToken, req.Ip, req.UserAgent)
	if err != nil {
		return nil, err
	}

	return dto.NewSessionResponse(tokens), nil
}

func (s *AuthServer) SignOut(_ context.Context, req *api.SignOutRequest) (*api.SignOutResponse, error) {
	if err := s.service.Session.SignOut(req.RefreshToken); err != nil {
		return nil, err
	}
	return &api.SignOutResponse{Message: "session closed"}, nil
}

func (s *AuthServer) GetAuthInfo(_ context.Context, req *api.GetAuthInfoRequest) (*api.GetAuthInfoResponse, error) {
	if len(req.Id) == 0 && len(req.Email) == 0 && len(req.Nickname) == 0 {
		return nil, fail.GrpcInvalidBody
	}

	identifiers := entity.UserIdentifiers{}
	userId, err := uuid.Parse(req.Id)
	if err == nil {
		identifiers.UserId = &userId
	}
	if len(req.Email) > 0 {
		identifiers.Email = &req.Email
	}
	if len(req.Nickname) > 0 {
		identifiers.Nickname = &req.Nickname
	}

	authInfo, err := s.service.Session.GetAuthInfo(identifiers)
	if err != nil {
		return nil, err
	}

	return dto.NewGetAuthInfoResponse(authInfo), nil
}

func (s *AuthServer) GetSessions(_ context.Context, req *api.GetSessionsRequest) (*api.GetSessionsResponse, error) {
	userId, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	sessions := s.service.Session.GetAll(userId)

	return dto.NewGetSessionsResponse(sessions), nil
}

func (s *AuthServer) EndSessions(_ context.Context, req *api.EndSessionsRequest) (*api.EndSessionsResponse, error) {
	userId, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	s.service.Session.DeleteMultiple(userId, req.Sessions)

	return &api.EndSessionsResponse{Message: "sessions deleted"}, nil
}
