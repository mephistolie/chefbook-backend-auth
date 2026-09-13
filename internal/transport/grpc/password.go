package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/utils/credentials"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *AuthServer) RequestPasswordReset(ctx context.Context, req *api.RequestPasswordResetRequest) (*api.RequestPasswordResetResponse, error) {
	if len(req.Email) == 0 && len(req.Username) == 0 {
		return nil, fail.GrpcInvalidBody
	}

	var email *string = nil
	var username *string = nil
	if len(req.Email) > 0 {
		email = &req.Email
	}
	if len(req.Username) > 0 {
		username = &req.Username
	}

	if err := s.service.Password.RequestReset(ctx, email, username, req.ResetPasswordLinkPattern); err != nil {
		return nil, err
	}
	return &api.RequestPasswordResetResponse{Message: "if the profile exists, reset link has been sent"}, nil
}

func (s *AuthServer) ResetPassword(ctx context.Context, req *api.ResetPasswordRequest) (*api.ResetPasswordResponse, error) {
	if err := credentials.ValidatePassword(req.NewPassword); err != nil {
		return nil, err
	}

	userId, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}
	if err = s.service.Password.Reset(ctx, userId, req.ResetCode, req.NewPassword); err != nil {
		return nil, err
	}
	return &api.ResetPasswordResponse{Message: "password reset"}, nil
}

func (s *AuthServer) ChangePassword(ctx context.Context, req *api.ChangePasswordRequest) (*api.ChangePasswordResponse, error) {
	if err := credentials.ValidatePassword(req.NewPassword); err != nil {
		return nil, err
	}

	userId, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fail.GrpcInvalidBody
	}
	if err = s.service.Password.Change(ctx, userId, req.OldPassword, req.NewPassword); err != nil {
		return nil, err
	}
	return &api.ChangePasswordResponse{Message: "password changed"}, nil
}
