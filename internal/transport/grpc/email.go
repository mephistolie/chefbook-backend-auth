package grpc

import (
	"context"
	"github.com/google/uuid"
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/utils/credentials"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/flow"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"strings"
)

func (s *AuthServer) StartEmailBinding(ctx context.Context, req *api.StartEmailBindingRequest) (*api.StartEmailBindingResponse, error) {
	email := strings.TrimSpace(req.Email)
	if err := credentials.ValidateEmail(email); err != nil {
		return nil, err
	}
	var err error
	switch req.Purpose {
	case "verify":
		err = s.service.Email.Verify(ctx, email, req.ConfirmationLinkPattern, nil)
	case "change":
		id, parseErr := uuid.Parse(req.UserId)
		if parseErr != nil {
			return nil, fail.GrpcInvalidBody
		}
		err = s.service.Email.Change(flow.WithBinding(ctx, req.FlowBinding), id, email, req.ConfirmationLinkPattern, req.RedirectUri, reauthenticationInput(req.Credentials))
	default:
		return nil, fail.GrpcInvalidBody
	}
	if err != nil {
		return nil, err
	}
	return &api.StartEmailBindingResponse{}, nil
}
func (s *AuthServer) ConfirmEmailBinding(ctx context.Context, req *api.ConfirmEmailBindingRequest) (*api.ConfirmEmailBindingResponse, error) {
	if req.Token == "" {
		return nil, fail.GrpcInvalidBody
	}
	result, err := s.service.Email.Confirm(ctx, req.Token, req.ConfirmationLinkPattern)
	if err != nil {
		return nil, err
	}
	return &api.ConfirmEmailBindingResponse{Purpose: result.Purpose, Status: result.Status}, nil
}
