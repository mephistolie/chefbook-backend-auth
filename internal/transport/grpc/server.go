package grpc

import (
	api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/dependencies/service"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/utils/nickname"
)

type AuthServer struct {
	service           service.Service
	nicknameValidator nickname.Validator
	api.UnimplementedAuthServiceServer
}

func NewServer(service service.Service) *AuthServer {
	return &AuthServer{
		service:           service,
		nicknameValidator: *nickname.NewValidator(),
	}
}
