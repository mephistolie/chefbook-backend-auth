package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *AuthServer) CheckNicknameAvailability(_ context.Context, req *api.CheckNicknameAvailabilityRequest) (*api.CheckNicknameAvailabilityResponse, error) {
	if err := s.nicknameValidator.Validate(req.Nickname); err != nil {
		return nil, err
	}

	available, err := s.service.Nickname.CheckAvailability(req.Nickname)
	return &api.CheckNicknameAvailabilityResponse{Available: available}, err
}

func (s *AuthServer) SetNickname(_ context.Context, req *api.SetNicknameRequest) (*api.SetNicknameResponse, error) {
	userId, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}
	if err = s.nicknameValidator.Validate(req.Nickname); err != nil {
		return nil, err
	}

	if err = s.service.Nickname.Set(userId, req.Nickname); err != nil {
		return nil, err
	}
	return &api.SetNicknameResponse{Message: "nickname set"}, nil
}
