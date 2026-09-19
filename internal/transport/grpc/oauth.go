package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/grpc/dto"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/utils/query"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/flow"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

func (s *AuthServer) RequestGoogleOAuth(ctx context.Context, req *api.RequestGoogleOAuthRequest) (*api.RequestGoogleOAuthResponse, error) {
	link, err := s.service.OAuth.GenerateGoogleLink(flow.WithBinding(ctx, req.FlowBinding), req.RedirectUrl)
	if err != nil {
		return nil, err
	}
	return &api.RequestGoogleOAuthResponse{Link: link, ExpirationTimestamp: timestamppb.New(time.Now().Add(flow.TTL))}, nil
}

func (s *AuthServer) SignInGoogle(ctx context.Context, req *api.SignInGoogleRequest) (*api.SessionResponse, error) {
	tokens, err := s.service.Session.SignInGoogle(
		flow.WithBinding(ctx, req.FlowBinding),
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

func (s *AuthServer) SignInGoogleToken(ctx context.Context, req *api.SignInGoogleTokenRequest) (*api.SessionResponse, error) {
	tokens, err := s.service.Session.SignInGoogleIdToken(ctx, req.Token, entity.ClientData{Ip: req.Ip, UserAgent: req.UserAgent})
	if err != nil {
		return nil, err
	}

	return dto.NewSessionResponse(tokens), nil
}

func (s *AuthServer) ConnectGoogle(ctx context.Context, req *api.ConnectGoogleRequest) (*api.ConnectGoogleResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	var created bool
	if req.IdToken != "" {
		if req.Code != "" || req.State != "" {
			return nil, fail.GrpcInvalidBody
		}
		created, err = s.service.OAuth.ConnectGoogleToken(ctx, id, req.IdToken)
	} else {
		if req.Code == "" || req.State == "" {
			return nil, fail.GrpcInvalidBody
		}
		created, err = s.service.OAuth.ConnectGoogle(flow.WithBinding(ctx, req.FlowBinding), id, req.Code, req.State, req.RedirectUrl)
	}
	if err != nil {
		return nil, err
	}
	return &api.ConnectGoogleResponse{Created: created}, nil
}

func (s *AuthServer) DeleteGoogleConnection(ctx context.Context, req *api.DeleteGoogleConnectionRequest) (*api.DeleteGoogleConnectionResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	err = s.service.OAuth.DeleteGoogleConnection(ctx, id)
	if err != nil {
		return nil, err
	}
	return &api.DeleteGoogleConnectionResponse{Message: "Google connection deleted"}, nil
}

func (s *AuthServer) RequestVkOAuth(ctx context.Context, req *api.RequestVkOAuthRequest) (*api.RequestVkOAuthResponse, error) {
	link, err := s.service.OAuth.GenerateVkLink(flow.WithBinding(ctx, req.FlowBinding), req.Display, req.ResponseType, req.RedirectUri)
	if err != nil {
		return nil, err
	}
	return &api.RequestVkOAuthResponse{Link: link, ExpirationTimestamp: timestamppb.New(time.Now().Add(flow.TTL))}, nil
}

func (s *AuthServer) SignInVk(ctx context.Context, req *api.SignInVkRequest) (*api.SessionResponse, error) {
	tokens, err := s.service.Session.SignInVk(
		flow.WithBinding(ctx, req.FlowBinding),
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

func (s *AuthServer) ConnectVk(ctx context.Context, req *api.ConnectVkRequest) (*api.ConnectVkResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	created, err := s.service.OAuth.ConnectVk(flow.WithBinding(ctx, req.FlowBinding), id, req.Code, req.State, req.RedirectUri)
	if err != nil {
		return nil, err
	}
	return &api.ConnectVkResponse{Created: created}, nil
}

func (s *AuthServer) DeleteVkConnection(ctx context.Context, req *api.DeleteVkConnectionRequest) (*api.DeleteVkConnectionResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	err = s.service.OAuth.DeleteVkConnection(ctx, id)
	if err != nil {
		return nil, err
	}
	return &api.DeleteVkConnectionResponse{Message: "VK connection deleted"}, nil
}
