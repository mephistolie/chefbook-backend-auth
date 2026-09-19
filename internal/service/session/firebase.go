package session

import (
	"context"
	"errors"
	"github.com/mephistolie/chefbook-backend-common/firebase"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (s *Service) importFirebaseProfile(ctx context.Context, email, password string) (entity.AuthInfo, error) {
	if s.firebase == nil {
		return entity.AuthInfo{}, authFail.GrpcInvalidCredentials
	}
	firebaseProfile, err := s.firebase.SignInWithContext(ctx, email, password)
	if err != nil {
		if errors.Is(err, firebase.ErrInvalidCredentials) {
			return entity.AuthInfo{}, authFail.GrpcInvalidCredentials
		}
		return entity.AuthInfo{}, status.Error(codes.Unavailable, "firebase unavailable")
	}
	authlog.Default.FirebaseImportStarted(ctx)

	if s.repo.IsFirebaseProfileConnected(ctx, firebaseProfile.LocalId) {
		authlog.Default.FirebaseIdentityOccupied(ctx)
		return entity.AuthInfo{}, authFail.GrpcInvalidCredentials
	}

	passwordHash, err := s.hashManager.Hash(password)
	if err != nil {
		authlog.Default.PasswordHashFailed(ctx, err)
		return entity.AuthInfo{}, fail.GrpcUnknown
	}

	profile, err := s.firebase.GetProfile(ctx, firebaseProfile.LocalId)
	if err != nil {
		authlog.Default.FirebaseProfileFetchFailed(ctx, err)
		return entity.AuthInfo{}, fail.GrpcUnknown
	}

	userId, msg, err := s.repo.CreateUser(ctx, entity.CredentialsHash{
		Email:        email,
		PasswordHash: &passwordHash,
	}, nil, entity.OAuth{})
	if err != nil {
		return entity.AuthInfo{}, err
	}
	go s.mq.PublishProfilesMessage(context.WithoutCancel(ctx), msg)

	go func() {
		ctx := context.WithoutCancel(ctx)
		msg, err := s.repo.ConnectFirebase(ctx, userId, firebaseProfile.LocalId, profile.CreationTimestamp)
		if err == nil {
			_ = s.mq.PublishProfilesMessage(ctx, msg)
			authlog.Default.FirebaseProfileConnected(ctx, userId.String())
		} else {
			authlog.Default.FirebaseProfileConnectFailed(ctx, userId.String(), err)
		}
	}()

	return s.repo.GetAuthInfoById(ctx, userId)
}

func (s *Service) connectFirebaseProfile(ctx context.Context, userId uuid.UUID, email string) error {
	if s.firebase == nil {
		return nil
	}
	profile, err := s.firebase.GetProfileByEmail(ctx, email)
	if err != nil {
		return fail.GrpcUnknown
	}
	msg, err := s.repo.ConnectFirebase(ctx, userId, profile.Id, profile.CreationTimestamp)
	if err != nil {
		return err
	}
	_ = s.mq.PublishProfilesMessage(ctx, msg)
	authlog.Default.FirebaseProfileConnected(ctx, userId.String())
	return nil
}
