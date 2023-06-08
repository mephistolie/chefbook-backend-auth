package dto

import (
	entity "github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"google.golang.org/protobuf/types/known/timestamppb"
)
import api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"

func NewGetAuthInfoResponse(info entity.AuthInfo) *api.GetAuthInfoResponse {
	nickname := ""
	if info.Nickname != nil {
		nickname = *info.Nickname
	}

	var oAuthPtr *api.OAuth = nil
	if info.OAuth.GoogleId != nil ||
		info.OAuth.VkId != nil {
		oAuth := api.OAuth{}
		if info.OAuth.GoogleId != nil {
			oAuth.GoogleId = *info.OAuth.GoogleId
		}
		if info.OAuth.VkId != nil {
			oAuth.VkId = *info.OAuth.VkId
		}
		oAuthPtr = &oAuth
	}

	return &api.GetAuthInfoResponse{
		Id:                    info.Id.String(),
		Email:                 info.Email,
		Nickname:              nickname,
		Role:                  info.Role,
		RegistrationTimestamp: timestamppb.New(info.RegistrationTimestamp),
		IsActivated:           info.IsActivated,
		IsBlocked:             info.IsBlocked,
		OAuth:                 oAuthPtr,
	}
}
