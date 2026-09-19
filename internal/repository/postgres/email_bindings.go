package postgres

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (r *Repository) StartEmailBinding(ctx context.Context, b entity.EmailBinding) error {
	token, err := opaqueToken()
	if err != nil {
		return fail.GrpcUnknown
	}
	b.Token = token
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fail.GrpcUnknown
	}
	defer tx.Rollback()
	var currentEmail string
	var activated, blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT email,activated,blocked FROM users WHERE user_id=$1 FOR UPDATE`, b.UserId).Scan(&currentEmail, &activated, &blocked); err != nil {
		return fail.GrpcUnknown
	}
	if b.Purpose == "verify" && (activated || blocked || currentEmail != b.Email) {
		return nil
	}

	// A resend keeps the proposed registration password bound to the outstanding proof.
	if b.Purpose == "verify" && b.PasswordHash == nil {
		err = tx.QueryRowContext(ctx, `SELECT password_hash FROM email_bindings WHERE user_id=$1 AND purpose='verify' AND expires_at>NOW()`, b.UserId).Scan(&b.PasswordHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fail.GrpcUnknown
		}
	}
	if b.Purpose == "change" {
		if blocked {
			return authFail.GrpcProfileIsBlocked
		}
		if currentEmail != b.OldEmail {
			return fail.CreateGrpcConflict("email_change_conflict", "email changed")
		}
		var deletion bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM delete_profile_requests WHERE user_id=$1)`, b.UserId).Scan(&deletion); err != nil {
			return fail.GrpcUnknown
		}
		if deletion {
			return authFail.GrpcAccountDeleting
		}
		var pending bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM email_bindings WHERE user_id=$1 AND purpose='change' AND expires_at>NOW())`, b.UserId).Scan(&pending); err != nil {
			return fail.GrpcUnknown
		}
		if pending {
			return fail.CreateGrpcConflict("email_change_pending", "email change already pending")
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM email_bindings WHERE user_id=$1 AND purpose=$2`, b.UserId, b.Purpose); err != nil {
		return fail.GrpcUnknown
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO email_bindings(token_hash,user_id,purpose,stage,old_email,email,password_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, tokenHash(token), b.UserId, b.Purpose, b.Stage, currentEmail, b.Email, b.PasswordHash, b.ExpiresAt); err != nil {
		return fail.GrpcUnknown
	}
	if err = queueBindingEmail(ctx, tx, b); err != nil {
		return err
	}
	return commitTransaction(ctx, tx)
}
func queueBindingEmail(ctx context.Context, tx *sql.Tx, b entity.EmailBinding) error {
	email := b.Email
	if b.Stage == "old" {
		email = b.OldEmail
	}
	// Replacing a request also replaces an unsent old email, so stale tokens aren't delivered later.
	if _, err := tx.ExecContext(ctx, `DELETE FROM email_deliveries WHERE user_id=$1 AND purpose=$2`, b.UserId, b.Purpose); err != nil {
		return fail.GrpcUnknown
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO email_deliveries(user_id,email,token,link_pattern,purpose,stage,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, b.UserId, email, b.Token, b.LinkPattern, b.Purpose, b.Stage, b.ExpiresAt)
	if err != nil {
		return fail.GrpcUnknown
	}
	return nil
}
func (r *Repository) ConfirmEmailBinding(ctx context.Context, token, pattern string) (entity.EmailConfirmation, error) {
	result := entity.EmailConfirmation{}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fail.GrpcUnknown
	}
	defer tx.Rollback()
	var id uuid.UUID
	if err = tx.QueryRowContext(ctx, `SELECT user_id FROM email_bindings WHERE token_hash=$1 AND expires_at>NOW()`, tokenHash(token)).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, authFail.GrpcInvalidActivationCode
		}
		return result, fail.GrpcUnknown
	}
	var email string
	var blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT email,blocked FROM users WHERE user_id=$1 FOR UPDATE`, id).Scan(&email, &blocked); err != nil {
		return result, fail.GrpcUnknown
	}
	var b entity.EmailBinding
	b.UserId = id
	b.LinkPattern = pattern
	err = tx.QueryRowContext(ctx, `SELECT purpose,stage,old_email,email,password_hash,expires_at FROM email_bindings WHERE token_hash=$1 AND expires_at>NOW() FOR UPDATE`, tokenHash(token)).Scan(&b.Purpose, &b.Stage, &b.OldEmail, &b.Email, &b.PasswordHash, &b.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return result, authFail.GrpcInvalidActivationCode
	}
	if err != nil {
		return result, fail.GrpcUnknown
	}
	if blocked {
		return result, authFail.GrpcProfileIsBlocked
	}
	if email != b.OldEmail {
		return result, authFail.GrpcInvalidActivationCode
	}
	var deleting bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM delete_profile_requests WHERE user_id=$1)`, id).Scan(&deleting); err != nil {
		return result, fail.GrpcUnknown
	}
	if deleting {
		return result, authFail.GrpcAccountDeleting
	}
	result.Purpose = b.Purpose
	switch b.Stage {
	case "verify":
		if _, err = tx.ExecContext(ctx, `UPDATE users SET activated=true,password=COALESCE($2,password) WHERE user_id=$1`, id, b.PasswordHash); err != nil {
			return result, fail.GrpcUnknown
		}
		result.Status = "verified"
	case "old":
		b.Token, err = opaqueToken()
		if err != nil {
			return result, fail.GrpcUnknown
		}
		b.Stage = "new"
		b.ExpiresAt = time.Now().Add(24 * time.Hour)
		if _, err = tx.ExecContext(ctx, `UPDATE email_bindings SET token_hash=$2,stage='new',expires_at=$3 WHERE token_hash=$1`, tokenHash(token), tokenHash(b.Token), b.ExpiresAt); err != nil {
			return result, fail.GrpcUnknown
		}
		if err = queueBindingEmail(ctx, tx, b); err != nil {
			return result, err
		}
		result.Status = "pendingNewEmail"
		return result, commitTransaction(ctx, tx)
	case "new":
		if _, err = tx.ExecContext(ctx, `UPDATE users SET email=$2 WHERE user_id=$1`, id, b.Email); err != nil {
			if isUniqueViolationError(err) {
				return result, fail.CreateGrpcConflict("email_unavailable", "email unavailable")
			}
			return result, fail.GrpcUnknown
		}
		result.Status = "changed"
	default:
		return result, authFail.GrpcInvalidActivationCode
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM email_bindings WHERE user_id=$1`, id); err != nil {
		return result, fail.GrpcUnknown
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM activation_codes WHERE user_id=$1`, id); err != nil {
		return result, fail.GrpcUnknown
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM email_deliveries WHERE user_id=$1`, id); err != nil {
		return result, fail.GrpcUnknown
	}
	if b.Stage == "new" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id=$1`, id); err != nil {
			return result, fail.GrpcUnknown
		}
	}
	return result, commitTransaction(ctx, tx)
}
func (r *Repository) DeliverEmail(ctx context.Context, send func(context.Context, entity.EmailDelivery) error) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fail.GrpcUnknown
	}
	defer tx.Rollback()
	var id int64
	var mail entity.EmailDelivery
	err = tx.QueryRowContext(ctx, `SELECT id,user_id,email,token,link_pattern,purpose,stage FROM email_deliveries WHERE next_attempt<=NOW() AND expires_at>NOW() ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &mail.UserId, &mail.Email, &mail.Token, &mail.LinkPattern, &mail.Purpose, &mail.Stage)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fail.GrpcUnknown
	}
	if err = send(ctx, mail); err != nil {
		_, err = tx.ExecContext(ctx, `UPDATE email_deliveries SET attempts=attempts+1,next_attempt=NOW()+interval '1 minute' WHERE id=$1`, id)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM email_deliveries WHERE id=$1`, id)
	}
	if err != nil {
		return false, fail.GrpcUnknown
	}
	return true, commitTransaction(ctx, tx)
}
