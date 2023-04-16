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
	firebaseProfile, err := s.firebase.SignIn(email, password)
	if err != nil {
		return entity.AuthInfo{}, authFail.GrpcInvalidCredentials
	}
	log.Infof("found Firebase profile %s for email %s; importing...", firebaseProfile.LocalId, email)

	if s.repo.IsFirebaseProfileConnected(firebaseProfile.LocalId) {
		log.Warnf("Firebase profile % already connected to other user", firebaseProfile.LocalId)
		return entity.AuthInfo{}, authFail.GrpcInvalidCredentials
	}

	passwordHash, err := s.hashManager.Hash(password)
	if err != nil {
		log.Error("unable to hash password: ", err)
		return entity.AuthInfo{}, fail.GrpcUnknown
	}

	profile, err := s.firebase.GetProfile(context.Background(), firebaseProfile.LocalId)
	if err != nil {
		log.Errorf("unable to get firebase profile %s data: %s", firebaseProfile.LocalId, err)
		return entity.AuthInfo{}, fail.GrpcUnknown
	}

	userId, err := s.repo.CreateUser(entity.CredentialsHash{
		Email:        email,
		PasswordHash: &passwordHash,
	}, nil, entity.OAuth{})
	if err != nil {
		return entity.AuthInfo{}, err
	}

	go s.repo.ConnectFirebase(userId, firebaseProfile.LocalId, profile.CreationTimestamp)

	return s.repo.GetAuthInfoById(userId)
}

func (s *Service) connectFirebaseProfile(userId uuid.UUID, email string) error {
	profile, err := s.firebase.GetProfileByEmail(context.Background(), email)
	if err != nil {
		return fail.GrpcUnknown
	}
	return s.repo.ConnectFirebase(userId, profile.Id, profile.CreationTimestamp)
}
