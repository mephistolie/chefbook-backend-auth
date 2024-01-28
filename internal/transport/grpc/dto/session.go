package dto

import (
	entity "github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sort"
)
import api "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"

func NewGetSessionsResponse(infos []entity.SessionInfo) *api.GetSessionsResponse {
	sessions := make([]*api.Session, len(infos))
	for i, info := range infos {
		session := api.Session{
			Id:          info.SessionId,
			Ip:          info.Ip,
			AccessPoint: info.AccessPoint,
			Mobile:      info.Mobile,
			AccessTime:  timestamppb.New(info.AccessTime),
			Location:    info.Location,
		}
		sessions[i] = &session
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].AccessTime.String() > sessions[i].AccessTime.String()
	})
	return &api.GetSessionsResponse{Sessions: sessions}
}

func NewSessionResponse(tokens entity.Tokens) *api.SessionResponse {
	var deletionTimestamp *timestamppb.Timestamp
	if tokens.DeletionTimestamp != nil {
		deletionTimestamp = timestamppb.New(*tokens.DeletionTimestamp)
	}

	return &api.SessionResponse{
		AccessToken:              tokens.AccessToken,
		RefreshToken:             tokens.RefreshToken,
		ExpirationTimestamp:      timestamppb.New(tokens.ExpirationTimestamp),
		ProfileDeletionTimestamp: deletionTimestamp,
	}
}
