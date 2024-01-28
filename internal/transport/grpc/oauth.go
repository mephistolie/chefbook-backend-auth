package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/grpc/dto"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/utils/query"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *AuthServer) RequestGoogleOAuth(_ context.Context, req *api.RequestGoogleOAuthRequest) (*api.RequestGoogleOAuthResponse, error) {
	return &api.RequestGoogleOAuthResponse{Link: s.service.OAuth.GenerateGoogleLink(req.RedirectUrl)}, nil
}

func (s *AuthServer) SignInGoogle(_ context.Context, req *api.SignInGoogleRequest) (*api.SessionResponse, error) {
	tokens, err := s.service.Session.SignInGoogle(
		entity.OAuthCredentials{
			Code:  query.Decode(req.Code),
			State: req.State,
		},
		entity.ClientData{
			Ip:        req.Ip,
			UserAgent: req.UserAgent,
		},
		req.RedirectUrl,
	)
	if err != nil {
		return nil, err
	}

	return dto.NewSessionResponse(tokens), nil
}

func (s *AuthServer) SignInGoogleToken(_ context.Context, req *api.SignInGoogleTokenRequest) (*api.SessionResponse, error) {
	tokens, err := s.service.Session.SignInGoogleToken(req.Token, entity.ClientData{Ip: req.Ip, UserAgent: req.UserAgent})
	if err != nil {
		return nil, err
	}

	return dto.NewSessionResponse(tokens), nil
}

func (s *AuthServer) ConnectGoogle(_ context.Context, req *api.ConnectGoogleRequest) (*api.ConnectGoogleResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	if err := s.service.OAuth.ConnectGoogle(id, query.Decode(req.Code), req.State, req.RedirectUrl); err != nil {
		return nil, err
	}

	return &api.ConnectGoogleResponse{Message: "Google profile connected"}, nil
}

func (s *AuthServer) DeleteGoogleConnection(_ context.Context, req *api.DeleteGoogleConnectionRequest) (*api.DeleteGoogleConnectionResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	err = s.service.OAuth.DeleteGoogleConnection(id)
	if err != nil {
		return nil, err
	}
	return &api.DeleteGoogleConnectionResponse{Message: "Google connection deleted"}, nil
}

func (s *AuthServer) RequestVkOAuth(_ context.Context, req *api.RequestVkOAuthRequest) (*api.RequestVkOAuthResponse, error) {
	link, err := s.service.OAuth.GenerateVkLink(req.Display, req.ResponseType, req.RedirectUri)
	if err != nil {
		return nil, err
	}
	return &api.RequestVkOAuthResponse{Link: link}, nil
}

func (s *AuthServer) SignInVk(_ context.Context, req *api.SignInVkRequest) (*api.SessionResponse, error) {
	tokens, err := s.service.Session.SignInVk(
		entity.OAuthCredentials{
			Code:  query.Decode(req.Code),
			State: req.State,
		},
		entity.ClientData{
			Ip:        req.Ip,
			UserAgent: req.UserAgent,
		},
		req.RedirectUri,
	)
	if err != nil {
		return nil, err
	}

	return dto.NewSessionResponse(tokens), nil
}

func (s *AuthServer) ConnectVk(_ context.Context, req *api.ConnectVkRequest) (*api.ConnectVkResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	if err := s.service.OAuth.ConnectVk(id, query.Decode(req.Code), req.State, req.RedirectUri); err != nil {
		return nil, err
	}

	return &api.ConnectVkResponse{Message: "VK profile connected"}, nil
}

func (s *AuthServer) DeleteVkConnection(_ context.Context, req *api.DeleteVkConnectionRequest) (*api.DeleteVkConnectionResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	err = s.service.OAuth.DeleteVkConnection(id)
	if err != nil {
		return nil, err
	}
	return &api.DeleteVkConnectionResponse{Message: "VK connection deleted"}, nil
}
