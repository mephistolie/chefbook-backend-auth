package session

import (
	"context"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *Service) importFirebaseProfile(ctx context.Context, email, password string) (entity.AuthInfo, error) {
	firebaseProfile, err := s.firebase.SignIn(email, password)
	if err != nil {
		return entity.AuthInfo{}, authFail.GrpcInvalidCredentials
	}
	log.AutoInfof("found Firebase profile %s for email %s; importing...", firebaseProfile.LocalId, email)

	if s.repo.IsFirebaseProfileConnected(ctx, firebaseProfile.LocalId) {
		log.AutoWarnf("Firebase profile %s already connected to other user", firebaseProfile.LocalId)
		return entity.AuthInfo{}, authFail.GrpcInvalidCredentials
	}

	passwordHash, err := s.hashManager.Hash(password)
	if err != nil {
		log.AutoError("unable to hash password: ", err)
		return entity.AuthInfo{}, fail.GrpcUnknown
	}

	profile, err := s.firebase.GetProfile(ctx, firebaseProfile.LocalId)
	if err != nil {
		log.AutoErrorf("unable to get firebase profile %s data: %s", firebaseProfile.LocalId, err)
		return entity.AuthInfo{}, fail.GrpcUnknown
	}

	userId, msg, err := s.repo.CreateUser(ctx, entity.CredentialsHash{
		Email:        email,
		PasswordHash: &passwordHash,
	}, nil, entity.OAuth{})
	if err != nil {
		return entity.AuthInfo{}, err
	}
	go s.mq.PublishProfilesMessage(msg)

	go func() {
		ctx := context.WithoutCancel(ctx)
		msg, err := s.repo.ConnectFirebase(ctx, userId, firebaseProfile.LocalId, profile.CreationTimestamp)
		if err == nil {
			_ = s.mq.PublishProfilesMessage(msg)
		}
	}()

	return s.repo.GetAuthInfoById(ctx, userId)
}

func (s *Service) connectFirebaseProfile(ctx context.Context, userId uuid.UUID, email string) error {
	profile, err := s.firebase.GetProfileByEmail(ctx, email)
	if err != nil {
		return fail.GrpcUnknown
	}
	msg, err := s.repo.ConnectFirebase(ctx, userId, profile.Id, profile.CreationTimestamp)
	if err != nil {
		return nil
	}
	_ = s.mq.PublishProfilesMessage(msg)
	return nil
}
