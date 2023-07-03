package session

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"github.com/mephistolie/chefbook-backend-common/tokens/access"
	"github.com/mssola/useragent"
	"sync"
	"time"
)

func (s *Service) Refresh(refreshToken, ip, userAgent string) (entity.Tokens, error) {
	authInfo, err := s.repo.GetAuthInfoByRefreshToken(refreshToken)
	if err != nil {
		return entity.Tokens{}, err
	}

	if authInfo.IsBlocked {
		log.Warnf("try to login blocked profile %s", authInfo.Id)
		_ = s.repo.DeleteSession(refreshToken)
		return entity.Tokens{}, authFail.GrpcProfileIsBlocked
	}

	tokenPair, session, err := s.createSessionEntity(authInfo, ip, userAgent)
	if err != nil {
		return entity.Tokens{}, err
	}

	return tokenPair, s.repo.UpdateSession(session, refreshToken)
}

func (s *Service) GetAll(userId uuid.UUID) []entity.SessionInfo {
	rawInfos := s.repo.GetSessions(userId)
	sessionsCount := len(rawInfos)

	locationMap := s.getIpLocationMap(rawInfos)

	infos := make([]entity.SessionInfo, sessionsCount)
	for i, rawInfo := range rawInfos {
		infos[i] = s.humanizeSessionInfo(rawInfo, locationMap[rawInfo.Ip])
	}

	return infos
}

func (s *Service) DeleteMultiple(userId uuid.UUID, sessionIds []int64) {
	s.repo.DeleteSessions(userId, sessionIds)
}

func (s *Service) createSessionEntity(
	authInfo entity.AuthInfo,
	ip string,
	userAgent string,
) (entity.Tokens, entity.SessionInput, error) {
	var (
		res entity.Tokens
		err error
	)
	res.AccessToken, err = s.tokenManager.CreateAccess(access.Payload{
		UserId:   authInfo.Id,
		Email:    authInfo.Email,
		Nickname: authInfo.Nickname,
		Role:     authInfo.Role,
		Deleted:  authInfo.DeletionTimestamp != nil,
	}, s.accessTokenTtl)
	if err != nil {
		log.Error("unable to create access token: ", err)
		return entity.Tokens{}, entity.SessionInput{}, fail.GrpcUnknown
	}

	res.RefreshToken = s.tokenManager.CreateRefresh()
	res.ExpirationTimestamp = time.Now().Add(s.accessTokenTtl)
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
