package postgres

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) GetAuthInfoByGoogleId(googleId string) (entity.AuthInfo, error) {
	return r.getAuthInfoByCondition(fmt.Sprintf("%s.google_id=$1", oauthTable), googleId)
}

func (r *Repository) GetAuthInfoByVkId(vkId int64) (entity.AuthInfo, error) {
	return r.getAuthInfoByCondition(fmt.Sprintf("%s.vk_id=$1", oauthTable), vkId)
}

func (r *Repository) ConnectGoogle(userId uuid.UUID, googleId string) error {
	query := fmt.Sprintf(`
			UPDATE %s
			SET google_id=$1
			WHERE user_id=$2
		`, oauthTable)
	if _, err := r.db.Exec(query, googleId, userId); err != nil {
		log.Warnf("Google profile %s is occupied: %s", googleId, err)
		return authFail.GrpcAccountOccupied
	}

	return nil
}

func (r *Repository) DeleteGoogleConnection(userId uuid.UUID) error {
	query := fmt.Sprintf(`
			UPDATE %s
			SET google_id=NULL
			WHERE user_id=$1
		`, oauthTable)
	if _, err := r.db.Exec(query, userId); err != nil {
		log.Errorf("unable to delete Google profile connection for user %s: %s", userId, err)
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) ConnectVk(userId uuid.UUID, vkId int64) error {
	query := fmt.Sprintf(`
			UPDATE %s
			SET vk_id=$1
			WHERE user_id=$2
		`, oauthTable)
	if _, err := r.db.Exec(query, vkId, userId); err != nil {
		log.Warnf("VK profile %s is occupied: %s", vkId, err)
		return authFail.GrpcAccountOccupied
	}

	return nil
}

func (r *Repository) DeleteVkConnection(userId uuid.UUID) error {
	query := fmt.Sprintf(`
			UPDATE %s
			SET vk_id=NULL
			WHERE user_id=$1
		`, oauthTable)
	if _, err := r.db.Exec(query, userId); err != nil {
		log.Errorf("unable to delete VK profile connection for user %s: %s", userId, err)
		return fail.GrpcUnknown
	}

	return nil
}
