package session

import (
	"context"
	"crypto/x509"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/random"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *Service) SignUp(ctx context.Context, credentials entity.SignUpCredentials, pattern string) (uuid.UUID, bool, error) {
	info, err := s.repo.GetAuthInfoByEmail(ctx, credentials.Email)
	if err == nil {
		if info.IsActivated || info.IsBlocked {
			return info.Id, info.IsActivated, nil
		}
		hash, err := s.hashManager.Hash(credentials.Password)
		if err != nil {
			return uuid.Nil, false, fail.GrpcUnknown
		}
		return info.Id, false, s.email.Verify(ctx, credentials.Email, pattern, &hash)
	}
	if status.Code(err) != codes.NotFound {
		return uuid.Nil, false, err
	}
	hash, marker, err := s.createNewUserData(ctx, credentials)
	if err != nil {
		return uuid.Nil, false, err
	}
	id, msg, err := s.repo.CreateUser(ctx, hash, marker, entity.OAuth{})
	if err != nil {
		return uuid.Nil, false, err
	}
	go s.mq.PublishProfilesMessage(context.WithoutCancel(ctx), msg)
	return id, false, s.email.Verify(ctx, credentials.Email, pattern, hash.PasswordHash)
}

func (s *Service) ActivateProfile(ctx context.Context, userId uuid.UUID, code string) error {
	return s.repo.ActivateProfile(ctx, userId, code)
}
func (s *Service) SignIn(ctx context.Context, credentials entity.SignInCredentials, client entity.ClientData) (entity.Tokens, error) {
	authInfo, err := s.repo.GetAuthInfoByIdentifiers(ctx, entity.UserIdentifiers{Email: credentials.Email, Username: credentials.Username})
	if err != nil {
		if status.Code(err) != codes.NotFound {
			return entity.Tokens{}, err
		}
		if credentials.Email == nil || s.firebase == nil {
			return entity.Tokens{}, authFail.GrpcInvalidCredentials
		}
		if authInfo, err = s.importFirebaseProfile(ctx, *credentials.Email, credentials.Password); err != nil {
			return entity.Tokens{}, err
		}
	}

	if err = s.hashManager.Validate(credentials.Password, authInfo.PasswordHash); err != nil {
		authlog.Default.PasswordInvalid(ctx, authInfo.Id.String())
		return entity.Tokens{}, authFail.GrpcInvalidCredentials
	}

	if err := s.checkProfileAvailability(ctx, authInfo); err != nil {
		return entity.Tokens{}, err
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

func (s *Service) createNewUserData(ctx context.Context, credentials entity.SignUpCredentials) (entity.CredentialsHash, *string, error) {
	passwordHash, err := s.hashManager.Hash(credentials.Password)
	if err != nil {
		authlog.Default.PasswordHashFailed(ctx, err)
		return entity.CredentialsHash{}, nil, fail.GrpcUnknown
	}
	activationCodeStr := random.DigitString(activationCodeLength)
	activationCode := &activationCodeStr
	return entity.CredentialsHash{
		Id:           credentials.Id,
		Email:        credentials.Email,
		PasswordHash: &passwordHash,
	}, activationCode, nil
}

func (s *Service) createSession(ctx context.Context, authInfo entity.AuthInfo, client entity.ClientData) (entity.Tokens, error) {
	authlog.Default.SessionCreationStarted(ctx, authInfo.Id.String())
	tokenPair, session, err := s.createSessionEntity(ctx, authInfo, client.Ip, client.UserAgent)
	if err != nil {
		return entity.Tokens{}, err
	}

	if tokenPair.SessionId, err = s.repo.CreateSession(ctx, session); err != nil {
		return entity.Tokens{}, err
	}

	go s.repo.DeleteOutdatedSessions(context.WithoutCancel(ctx), authInfo.Id, maxSessionsCount)
	go s.mail.SendNewLoginMail(context.WithoutCancel(ctx), authInfo.Id, authInfo.Email, client, time.Now())

	return tokenPair, nil
}

func (s *Service) checkProfileAvailability(ctx context.Context, authInfo entity.AuthInfo) error {
	if authInfo.IsActivated == false {
		authlog.Default.ProfileNotActivated(ctx, authInfo.Id.String())
		return authFail.GrpcProfileNotActivated
	}
	if authInfo.IsBlocked == true {
		authlog.Default.ProfileBlocked(ctx, authInfo.Id.String())
		return authFail.GrpcProfileIsBlocked
	}
	return nil
}
