package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *AuthServer) GetProfileDeletionStatus(_ context.Context, req *api.GetProfileDeletionStatusRequest) (*api.GetProfileDeletionStatusResponse, error) {
	userId, err := uuid.Parse(req.ProfileId)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	timestamp, deleted := s.service.ProfileDeletion.GetInfo(userId)
	if err != nil {
		return nil, err
	}

	var deletionTimestamp *timestamppb.Timestamp
	if timestamp != nil {
		deletionTimestamp = timestamppb.New(*timestamp)
	}

	return &api.GetProfileDeletionStatusResponse{DeletionTimestamp: deletionTimestamp, Deleted: deleted}, nil
}

func (s *AuthServer) DeleteProfile(_ context.Context, req *api.DeleteProfileRequest) (*api.DeleteProfileResponse, error) {
	userId, err := uuid.Parse(req.ProfileId)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	timestamp, err := s.service.ProfileDeletion.Request(userId, req.Password, req.DeleteSharedData)
	if err != nil {
		return nil, err
	}

	return &api.DeleteProfileResponse{DeletionTimestamp: timestamppb.New(timestamp)}, nil
}

func (s *AuthServer) CancelProfileDeletion(_ context.Context, req *api.CancelProfileDeletionRequest) (*api.CancelProfileDeletionResponse, error) {
	userId, err := uuid.Parse(req.ProfileId)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}

	if err = s.service.ProfileDeletion.Cancel(userId); err != nil {
		return nil, err
	}

	return &api.CancelProfileDeletionResponse{Message: "delete profile request canceled"}, nil
}
