package dto

import (
	entity "github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"google.golang.org/protobuf/types/known/timestamppb"
)
import api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"

const (
	roleMember = "member"
	roleAdmin  = "admin"
)

func NewGetAuthInfoResponse(info entity.AuthInfo) *api.GetAuthInfoResponse {
	nickname := ""
	googleId := ""
	var vkId int64 = -1
	if info.Nickname != nil {
		nickname = *info.Nickname
	}
	if info.OAuth.GoogleId != nil {
		googleId = *info.OAuth.GoogleId
	}
	if info.OAuth.VkId != nil {
		vkId = *info.OAuth.VkId
	}

	role := api.GetAuthInfoResponse_MEMBER
	if info.Role == roleAdmin {
		role = api.GetAuthInfoResponse_ADMIN
	}

	return &api.GetAuthInfoResponse{
		Id:                    info.Id.String(),
		Email:                 info.Email,
		Nickname:              nickname,
		Role:                  role,
		RegistrationTimestamp: timestamppb.New(info.RegistrationTimestamp),
		IsActivated:           info.IsActivated,
		IsBlocked:             info.IsBlocked,
		OAuth: &api.OAuth{
			GoogleId: googleId,
			VkId:     vkId,
		},
	}
}