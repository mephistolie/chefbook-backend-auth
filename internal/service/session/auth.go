package session

import (
	"context"
	"crypto/x509"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/random"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (s *Service) SignUp(ctx context.Context, credentials entity.SignUpCredentials, activationLinkPattern string) (uuid.UUID, bool, error) {
	if authInfo, err := s.repo.GetAuthInfoByEmail(ctx, credentials.Email); err == nil {
		return s.resendActivationMail(ctx, authInfo, credentials.Password, activationLinkPattern)
	}

	if authInfo, err := s.importFirebaseProfile(ctx, credentials.Email, credentials.Password); err == nil {
		return authInfo.Id, true, nil
	}

	credentialsHash, activationCode, err := s.createNewUserData(credentials)
	if err != nil {
		return uuid.UUID{}, false, err
	}

	userId, msg, err := s.repo.CreateUser(ctx, credentialsHash, activationCode, entity.OAuth{})
	if err != nil {
		return uuid.UUID{}, activationCode == nil, err
	}
	go s.mq.PublishProfilesMessage(msg)

	if activationCode != nil {
		go s.mail.SendProfileActivationMail(userId, credentials.Email, *activationCode, activationLinkPattern)
	}

	return userId, activationCode == nil, nil
}

func (s *Service) ActivateProfile(ctx context.Context, userId uuid.UUID, code string) error {
	return s.repo.ActivateProfile(ctx, userId, code)
}
func (s *Service) SignIn(ctx context.Context, credentials entity.SignInCredentials, client entity.ClientData) (entity.Tokens, error) {
	authInfo, err := s.repo.GetAuthInfoByIdentifiers(ctx, entity.UserIdentifiers{Email: credentials.Email, Nickname: credentials.Nickname})
	if err != nil {
		if credentials.Email == nil || s.firebase == nil {
			return entity.Tokens{}, err
		}
		if authInfo, err = s.importFirebaseProfile(ctx, *credentials.Email, credentials.Password); err != nil {
			return entity.Tokens{}, err
		}
	}

	if err := s.checkProfileAvailability(authInfo); err != nil {
		return entity.Tokens{}, err
	}
	if err = s.hashManager.Validate(credentials.Password, authInfo.PasswordHash); err != nil {
		log.Infof("invalid password for user %s: %s", authInfo.Id, err)
		return entity.Tokens{}, authFail.GrpcInvalidCredentials
	}

	return s.createSession(ctx, authInfo, client)
}

func (s *Service) GetAccessTokenPublicKey() []byte {
	key := s.tokenManager.GetAccessPublicKey()
	return x509.MarshalPKCS1PublicKey(key)
}

func (s *Service) SignOut(ctx context.Context, refreshToken string) error {
	return s.repo.DeleteSession(ctx, refreshToken)
}

func (s *Service) GetAuthInfo(ctx context.Context, identifiers entity.UserIdentifiers) (entity.AuthInfo, error) {
	return s.repo.GetAuthInfoByIdentifiers(ctx, identifiers)
}

func (s *Service) createNewUserData(credentials entity.SignUpCredentials) (entity.CredentialsHash, *string, error) {
	passwordHash, err := s.hashManager.Hash(credentials.Password)
	if err != nil {
		log.Error("unable to hash password: ", err)
		return entity.CredentialsHash{}, nil, fail.GrpcUnknown
	}
	var activationCode *string = nil
	if !s.mail.IsStub {
		activationCodeStr := random.DigitString(activationCodeLength)
		activationCode = &activationCodeStr
	}
	return entity.CredentialsHash{
		Id:           credentials.Id,
		Email:        credentials.Email,
		PasswordHash: &passwordHash,
	}, activationCode, nil
}

func (s *Service) resendActivationMail(ctx context.Context, authInfo entity.AuthInfo, password, linkPattern string) (uuid.UUID, bool, error) {
	if authInfo.IsActivated {
		log.Warnf("user with email %s already exists", authInfo.Email)
		return uuid.UUID{}, false, authFail.GrpcUserAlreadyExists
	}

	if err := s.hashManager.Validate(password, authInfo.PasswordHash); err != nil {
		passwordHash, err := s.hashManager.Hash(password)
		if err != nil {
			log.Errorf("unable to hash password: %s", err)
			return uuid.UUID{}, false, fail.GrpcUnknown
		}
		err = s.repo.SetPassword(ctx, authInfo.Id, passwordHash)
		if err != nil {
			return uuid.UUID{}, false, fail.GrpcUnknown
		}
	}

	activationCode, err := s.repo.GetProfileActivationCode(ctx, authInfo.Id)
	if err != nil {
		return uuid.UUID{}, false, fail.GrpcUnknown
	}

	go s.mail.SendProfileActivationMail(authInfo.Id, authInfo.Email, activationCode, linkPattern)

	return authInfo.Id, false, nil
}

func (s *Service) createSession(ctx context.Context, authInfo entity.AuthInfo, client entity.ClientData) (entity.Tokens, error) {
	log.Infof("creating session for user %s with IP %s...", authInfo.Id, client.Ip)
	tokenPair, session, err := s.createSessionEntity(ctx, authInfo, client.Ip, client.UserAgent)
	if err != nil {
		return entity.Tokens{}, err
	}

	if err = s.repo.CreateSession(ctx, session); err != nil {
		return entity.Tokens{}, err
	}

	go s.repo.DeleteOutdatedSessions(context.WithoutCancel(ctx), authInfo.Id, maxSessionsCount)
	go s.mail.SendNewLoginMail(authInfo.Email, client, time.Now())

	return tokenPair, nil
}

func (s *Service) checkProfileAvailability(authInfo entity.AuthInfo) error {
	if authInfo.IsActivated == false {
		log.Infof("try to login not activated profile %s", authInfo.Id)
		return authFail.GrpcProfileNotActivated
	}
	if authInfo.IsBlocked == true {
		log.Warnf("try to login blocked profile %s", authInfo.Id)
		return authFail.GrpcProfileIsBlocked
	}
	return nil
}
