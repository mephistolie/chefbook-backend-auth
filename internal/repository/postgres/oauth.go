package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) GetAuthInfoByGoogleId(ctx context.Context, googleId string) (entity.AuthInfo, error) {
	return r.getAuthInfoByCondition(ctx, fmt.Sprintf("%s.google_id=$1", oauthTable), googleId)
}

func (r *Repository) GetAuthInfoByVkId(ctx context.Context, vkId int64) (entity.AuthInfo, error) {
	return r.getAuthInfoByCondition(ctx, fmt.Sprintf("%s.vk_id=$1", oauthTable), vkId)
}

func (r *Repository) ConnectGoogle(ctx context.Context, id uuid.UUID, providerId string) (bool, error) {
	return r.connectIdentity(ctx, id, "google_id", providerId)
}

func (r *Repository) DeleteGoogleConnection(ctx context.Context, id uuid.UUID) error {
	return r.disconnectIdentity(ctx, id, "google_id")
}

func (r *Repository) ConnectVk(ctx context.Context, id uuid.UUID, providerId int64) (bool, error) {
	return r.connectIdentity(ctx, id, "vk_id", providerId)
}

func (r *Repository) DeleteVkConnection(ctx context.Context, id uuid.UUID) error {
	return r.disconnectIdentity(ctx, id, "vk_id")
}

func (r *Repository) connectIdentity(ctx context.Context, id uuid.UUID, column string, value interface{}) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fail.GrpcUnknown
	}
	defer tx.Rollback()
	var blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT blocked FROM users WHERE user_id=$1 FOR UPDATE`, id).Scan(&blocked); err != nil {
		return false, fail.GrpcUnknown
	}
	if blocked {
		return false, authFail.GrpcProfileIsBlocked
	}
	var deleting bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM delete_profile_requests WHERE user_id=$1)`, id).Scan(&deleting); err != nil {
		return false, fail.GrpcUnknown
	}
	if deleting {
		return false, authFail.GrpcAccountDeleting
	}
	var old *string
	if err = tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s::text FROM oauth WHERE user_id=$1 FOR UPDATE`, column), id).Scan(&old); err != nil {
		return false, fail.GrpcUnknown
	}
	if old != nil {
		if *old == fmt.Sprint(value) {
			return false, nil
		}
		return false, authFail.GrpcAccountOccupied
	}
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE oauth SET %s=$2 WHERE user_id=$1`, column), id, value); err != nil {
		if isUniqueViolationError(err) {
			return false, authFail.GrpcAccountOccupied
		}
		return false, fail.GrpcUnknown
	}
	return true, commitTransaction(ctx, tx)
}

func (r *Repository) disconnectIdentity(ctx context.Context, id uuid.UUID, column string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fail.GrpcUnknown
	}
	defer tx.Rollback()
	var blocked, hasPassword bool
	if err = tx.QueryRowContext(ctx, `SELECT blocked,COALESCE(octet_length(password)>0,false) FROM users WHERE user_id=$1 FOR UPDATE`, id).Scan(&blocked, &hasPassword); err != nil {
		return fail.GrpcUnknown
	}
	if blocked {
		return authFail.GrpcProfileIsBlocked
	}
	var deleting bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM delete_profile_requests WHERE user_id=$1)`, id).Scan(&deleting); err != nil {
		return fail.GrpcUnknown
	}
	if deleting {
		return authFail.GrpcAccountDeleting
	}
	var google, vk *string
	if err = tx.QueryRowContext(ctx, `SELECT google_id,vk_id::text FROM oauth WHERE user_id=$1 FOR UPDATE`, id).Scan(&google, &vk); err != nil {
		return fail.GrpcUnknown
	}
	if (column == "google_id" && google == nil) || (column == "vk_id" && vk == nil) {
		return nil
	}
	if !hasPassword && (google == nil || vk == nil) {
		return authFail.GrpcFewSignInMethods
	}
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE oauth SET %s=NULL WHERE user_id=$1`, column), id); err != nil {
		return fail.GrpcUnknown
	}
	return commitTransaction(ctx, tx)
}
