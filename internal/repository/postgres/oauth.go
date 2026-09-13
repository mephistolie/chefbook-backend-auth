package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) GetAuthInfoByGoogleId(ctx context.Context, googleId string) (entity.AuthInfo, error) {
	return r.getAuthInfoByCondition(ctx, fmt.Sprintf("%s.google_id=$1", oauthTable), googleId)
}

func (r *Repository) GetAuthInfoByVkId(ctx context.Context, vkId int64) (entity.AuthInfo, error) {
	return r.getAuthInfoByCondition(ctx, fmt.Sprintf("%s.vk_id=$1", oauthTable), vkId)
}

func (r *Repository) ConnectGoogle(ctx context.Context, userId uuid.UUID, googleId string) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET google_id=$1
		WHERE user_id=$2
	`, oauthTable)
	if _, err := r.db.ExecContext(ctx, query, googleId, userId); err != nil {
		authlog.Default.OAuthIdentityOccupied(ctx, authlog.OAuthData{
			Provider: "google",
			UserID:   userId.String(),
		})
		return authFail.GrpcAccountOccupied
	}

	return nil
}

func (r *Repository) DeleteGoogleConnection(ctx context.Context, userId uuid.UUID) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET google_id=NULL
		WHERE user_id=$1
	`, oauthTable)
	if _, err := r.db.ExecContext(ctx, query, userId); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "DeleteGoogleConnection",
			UserID:    userId.String(),
			Entity:    "oauth_connection",
		}, err)
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) ConnectVk(ctx context.Context, userId uuid.UUID, vkId int64) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET vk_id=$1
		WHERE user_id=$2
	`, oauthTable)
	if _, err := r.db.ExecContext(ctx, query, vkId, userId); err != nil {
		authlog.Default.OAuthIdentityOccupied(ctx, authlog.OAuthData{
			Provider: "vk",
			UserID:   userId.String(),
		})
		return authFail.GrpcAccountOccupied
	}

	return nil
}

func (r *Repository) DeleteVkConnection(ctx context.Context, userId uuid.UUID) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET vk_id=NULL
		WHERE user_id=$1
	`, oauthTable)
	if _, err := r.db.ExecContext(ctx, query, userId); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "DeleteVkConnection",
			UserID:    userId.String(),
			Entity:    "oauth_connection",
		}, err)
		return fail.GrpcUnknown
	}

	return nil
}
