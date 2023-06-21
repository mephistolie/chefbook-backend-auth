package dto

import (
	entity "github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"google.golang.org/protobuf/types/known/timestamppb"
)
import api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"

func NewGetAuthInfoResponse(info entity.AuthInfo) *api.GetAuthInfoResponse {
	var oAuth *api.OAuth = nil
	if info.OAuth.GoogleId != nil || info.OAuth.VkId != nil {
		oAuth = &api.OAuth{
			GoogleId: info.OAuth.GoogleId,
			VkId:     info.OAuth.VkId,
		}
	}

	var deletionTimestamp *timestamppb.Timestamp
	if info.DeletionTimestamp != nil {
		deletionTimestamp = timestamppb.New(*info.DeletionTimestamp)
	}

	return &api.GetAuthInfoResponse{
		Id:                    info.Id.String(),
		Email:                 info.Email,
		Nickname:              info.Nickname,
		Role:                  info.Role,
		RegistrationTimestamp: timestamppb.New(info.RegistrationTimestamp),
		IsActivated:           info.IsActivated,
		IsBlocked:             info.IsBlocked,
		DeletionTimestamp:     deletionTimestamp,
		OAuth:                 oAuth,
	}
}
