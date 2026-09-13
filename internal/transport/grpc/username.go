package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *AuthServer) GetVisibleNames(ctx context.Context, req *api.GetVisibleNamesRequest) (*api.GetVisibleNamesResponse, error) {
	var userIds []uuid.UUID
	for _, rawId := range req.UserIds {
		if userId, err := uuid.Parse(rawId); err == nil {
			userIds = append(userIds, userId)
		}
	}

	response, err := s.service.Username.Get(ctx, userIds)

	visibleNames := make(map[string]string)
	for id, name := range response {
		visibleNames[id.String()] = name
	}

	return &api.GetVisibleNamesResponse{UserVisibleNames: visibleNames}, err
}

func (s *AuthServer) CheckUsernameAvailability(ctx context.Context, req *api.CheckUsernameAvailabilityRequest) (*api.CheckUsernameAvailabilityResponse, error) {
	if err := s.usernameValidator.Validate(req.Username); err != nil {
		return nil, err
	}

	available, err := s.service.Username.CheckAvailability(ctx, req.Username)
	return &api.CheckUsernameAvailabilityResponse{Available: available}, err
}

func (s *AuthServer) SetUsername(ctx context.Context, req *api.SetUsernameRequest) (*api.SetUsernameResponse, error) {
	userId, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}
	if err = s.usernameValidator.Validate(req.Username); err != nil {
		return nil, err
	}

	if err = s.service.Username.Set(ctx, userId, req.Username); err != nil {
		return nil, err
	}
	return &api.SetUsernameResponse{Message: "username set"}, nil
}
