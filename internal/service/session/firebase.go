package session

import (
	"context"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *Service) importFirebaseProfile(email, password string) (entity.AuthInfo, error) {
	googleProfile, err := s.firebase.SignIn(email, password)
	if err != nil {
		return entity.AuthInfo{}, authFail.GrpcInvalidCredentials
	}
	log.Infof("found Firebase profile for email %s; importing...", email)

	passwordHash, err := s.hashManager.Hash(password)
	if err != nil {
		log.Error("unable to hash password: ", err)
		return entity.AuthInfo{}, fail.GrpcUnknown
	}

	profile, err := s.firebase.GetProfile(context.Background(), googleProfile.LocalId)
	if err != nil {
		log.Errorf("unable to get firebase profile %s data: %s", googleProfile.LocalId, err)
		return entity.AuthInfo{}, fail.GrpcUnknown
	}

	userId, err := s.repo.CreateUser(entity.CredentialsHash{
		Email:        email,
		PasswordHash: &passwordHash,
	}, nil, entity.OAuth{})
	if err != nil {
		return entity.AuthInfo{}, err
	}

	go func() {
		if err := s.repo.ConnectFirebase(userId, googleProfile.LocalId, profile.CreationTimestamp); err != nil {
			log.Errorf("unable to connect firebase profile %s for user %s: %s", googleProfile.LocalId, userId, err)
		}
	}()

	return s.repo.GetAuthInfoById(userId)
}

func (s *Service) connectFirebaseProfile(userId uuid.UUID, email string) error {
	profile, err := s.firebase.GetProfileByEmail(context.Background(), email)
	if err != nil {
		return fail.GrpcUnknown
	}
	return s.repo.ConnectFirebase(userId, profile.Id, profile.CreationTimestamp)
}
