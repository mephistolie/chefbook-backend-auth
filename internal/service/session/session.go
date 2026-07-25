package session

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"github.com/mephistolie/chefbook-backend-common/subscription"
	"github.com/mephistolie/chefbook-backend-common/tokens/access"
	subscriptionApi "github.com/mephistolie/chefbook-backend-subscription/api/proto/implementation/v1"
	"github.com/mssola/useragent"
	"sync"
	"time"
)

func (s *Service) Refresh(ctx context.Context, refreshToken, ip, userAgent string) (entity.Tokens, error) {
	authInfo, err := s.repo.GetAuthInfoByRefreshToken(ctx, refreshToken)
	if err != nil {
		return entity.Tokens{}, err
	}

	if authInfo.IsBlocked {
		log.AutoWarnf("try to login blocked profile %s", authInfo.Id)
		_ = s.repo.DeleteSession(ctx, refreshToken)
		return entity.Tokens{}, authFail.GrpcProfileIsBlocked
	}

	tokenPair, session, err := s.createSessionEntity(ctx, authInfo, ip, userAgent)
	if err != nil {
		return entity.Tokens{}, err
	}

	return tokenPair, s.repo.UpdateSession(ctx, session, refreshToken)
}

func (s *Service) GetAll(ctx context.Context, userId uuid.UUID) []entity.SessionInfo {
	rawInfos := s.repo.GetSessions(ctx, userId)
	sessionsCount := len(rawInfos)

	locationMap := s.getIpLocationMap(rawInfos)

	infos := make([]entity.SessionInfo, sessionsCount)
	for i, rawInfo := range rawInfos {
		infos[i] = s.humanizeSessionInfo(rawInfo, locationMap[rawInfo.Ip])
	}

	return infos
}

func (s *Service) DeleteMultiple(ctx context.Context, userId uuid.UUID, sessionIds []int64) {
	s.repo.DeleteSessions(ctx, userId, sessionIds)
}

func (s *Service) createSessionEntity(
	ctx context.Context,
	authInfo entity.AuthInfo,
	ip string,
	userAgent string,
) (entity.Tokens, entity.SessionInput, error) {
	var (
		res  entity.Tokens
		err  error
		plan = subscription.PlanFree
	)

	if sub, err := s.grpc.Subscription.GetProfileCurrentSubscription(
		ctx,
		&subscriptionApi.GetProfileCurrentSubscriptionRequest{UserId: authInfo.Id.String()},
	); err == nil {
		plan = sub.Plan
	}

	res.ProfileId = authInfo.Id
	res.AccessToken, err = s.tokenManager.CreateAccess(access.Payload{
		UserId:           authInfo.Id,
		Email:            authInfo.Email,
		Nickname:         authInfo.Nickname,
		Role:             authInfo.Role,
		SubscriptionPlan: plan,
		Deleted:          authInfo.DeletionTimestamp != nil,
	}, s.accessTokenTtl)
	if err != nil {
		log.AutoError("unable to create access token: ", err)
		return entity.Tokens{}, entity.SessionInput{}, fail.GrpcUnknown
	}

	res.RefreshToken = s.tokenManager.CreateRefresh()
	res.ExpirationTimestamp = time.Now().Add(s.refreshTokenTtl)
	res.DeletionTimestamp = authInfo.DeletionTimestamp

	return res, entity.SessionInput{
		UserId:       authInfo.Id,
		RefreshToken: res.RefreshToken,
		Ip:           ip,
		UserAgent:    userAgent,
		ExpiresAt:    res.ExpirationTimestamp,
	}, nil
}

func (s *Service) getIpLocationMap(infos []entity.SessionRawInfo) map[string]string {
	uniqueIps := map[string]bool{}
	for _, info := range infos {
		uniqueIps[info.Ip] = true
	}

	var wg sync.WaitGroup
	wg.Add(len(uniqueIps))

	locationMap := map[string]string{}
	for ip := range uniqueIps {
		ip := ip
		go func() {
			defer wg.Done()
			locationMap[ip] = s.ipInfoProvider.GetLocation(ip)
		}()
	}

	wg.Wait()
	return locationMap
}

func (s *Service) humanizeSessionInfo(rawInfo entity.SessionRawInfo, location string) entity.SessionInfo {
	ua := useragent.New(rawInfo.UserAgent)
	var accessPoint string
	if ua.Mobile() {
		accessPoint = ua.Model()
	} else {
		browser, version := ua.Browser()
		accessPoint = fmt.Sprintf("%s %s, %s", browser, version, ua.OS())
	}
	return entity.SessionInfo{
		SessionId:   rawInfo.SessionId,
		UserId:      rawInfo.UserId,
		Ip:          rawInfo.Ip,
		AccessPoint: accessPoint,
		Mobile:      ua.Mobile(),
		AccessTime:  rawInfo.AccessTime,
		Location:    location,
	}
}
