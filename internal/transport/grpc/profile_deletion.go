package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/flow"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *AuthServer) GetProfileDeletionStatus(ctx context.Context, req *api.GetProfileDeletionStatusRequest) (*api.GetProfileDeletionStatusResponse, error) {
	userId, err := uuid.Parse(req.ProfileId)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	timestamp, deleted := s.service.ProfileDeletion.GetInfo(ctx, userId)
	if err != nil {
		return nil, err
	}

	var deletionTimestamp *timestamppb.Timestamp
	if timestamp != nil {
		deletionTimestamp = timestamppb.New(*timestamp)
	}

	return &api.GetProfileDeletionStatusResponse{DeletionTimestamp: deletionTimestamp, Deleted: deleted}, nil
}

func (s *AuthServer) DeleteProfile(ctx context.Context, req *api.DeleteProfileRequest) (*api.DeleteProfileResponse, error) {
	userId, err := uuid.Parse(req.ProfileId)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	credentials := reauthenticationInput(req.Credentials)
	if req.Credentials == nil {
		credentials = entity.Reauthentication{Method: "password", Password: req.Password}
	}
	request, err := s.service.ProfileDeletion.Request(flow.WithBinding(ctx, req.FlowBinding), userId, credentials, req.DeleteSharedData, req.RedirectUri)
	if err != nil {
		return nil, err
	}

	return &api.DeleteProfileResponse{DeletionTimestamp: timestamppb.New(request.Timestamp), DeleteSharedData: request.WithSharedData}, nil
}

func (s *AuthServer) CancelProfileDeletion(ctx context.Context, req *api.CancelProfileDeletionRequest) (*api.CancelProfileDeletionResponse, error) {
	userId, err := uuid.Parse(req.ProfileId)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	if err = s.service.ProfileDeletion.Cancel(ctx, userId); err != nil {
		return nil, err
	}

	return &api.CancelProfileDeletionResponse{Message: "delete profile request canceled"}, nil
}

func (s *AuthServer) UpdateProfileDeletion(ctx context.Context, req *api.UpdateProfileDeletionRequest) (*api.UpdateProfileDeletionResponse, error) {
	id, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}
	request, err := s.service.ProfileDeletion.Update(ctx, id, req.DeleteSharedData)
	if err != nil {
		return nil, err
	}
	return &api.UpdateProfileDeletionResponse{DeletionTimestamp: timestamppb.New(request.Timestamp), DeleteSharedData: request.WithSharedData}, nil
}
func reauthenticationInput(c *api.Reauthentication) entity.Reauthentication {
	if c == nil {
		return entity.Reauthentication{}
	}
	return entity.Reauthentication{Method: c.Method, Password: c.Password, IdToken: c.IdToken, Code: c.Code, State: c.State}
}
