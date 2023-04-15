package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/utils/credentials"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *AuthServer) RequestRequestPasswordReset(_ context.Context, req *api.RequestPasswordResetRequest) (*api.RequestPasswordResetResponse, error) {
	if len(req.Email) == 0 && len(req.Nickname) == 0 {
		return nil, fail.GrpcInvalidBody
	}

	var email *string = nil
	var nickname *string = nil
	if len(req.Email) > 0 {
		email = &req.Email
	}
	if len(req.Nickname) > 0 {
		nickname = &req.Nickname
	}

	if err := s.service.Password.RequestReset(email, nickname); err != nil {
		return nil, err
	}
	return &api.RequestPasswordResetResponse{Message: "if the profile exists, reset link has been sent"}, nil
}

func (s *AuthServer) ResetPassword(_ context.Context, req *api.ResetPasswordRequest) (*api.ResetPasswordResponse, error) {
	if err := credentials.ValidatePassword(req.NewPassword); err != nil {
		return nil, err
	}

	userId, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}
	if err = s.service.Password.Reset(userId, req.ResetCode, req.NewPassword); err != nil {
		return nil, err
	}
	return &api.ResetPasswordResponse{Message: "password reset"}, nil
}

func (s *AuthServer) ChangePassword(_ context.Context, req *api.ChangePasswordRequest) (*api.ChangePasswordResponse, error) {
	if err := credentials.ValidatePassword(req.NewPassword); err != nil {
		return nil, err
	}

	userId, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}
	if err = s.service.Password.Change(userId, req.OldPassword, req.NewPassword); err != nil {
		return nil, err
	}
	return &api.ChangePasswordResponse{Message: "password changed"}, nil
}
