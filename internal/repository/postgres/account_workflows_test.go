package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func mockRepository(t *testing.T) (*Repository, sqlmock.Sqlmock) {
	t.Helper()
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	return NewRepository(sqlx.NewDb(db, "sqlmock"), 24*time.Hour), m
}
func TestRefreshRotationPreservesIDAndRejectsAlreadyConsumedToken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing bool
	}{{"existing", false}, {"already rotated", true}} {
		t.Run(tc.name, func(t *testing.T) {
			r, m := mockRepository(t)
			session := entity.SessionInput{RefreshToken: "new", Ip: "127.0.0.1", UserAgent: "app", ExpiresAt: time.Now().Add(time.Hour)}
			q := m.ExpectQuery(`UPDATE sessions SET refresh_token=.*WHERE refresh_token=.*AND expires_at>NOW\(\) RETURNING session_id`).WithArgs("new", "127.0.0.1", "app", session.ExpiresAt, "old")
			if tc.missing {
				q.WillReturnError(sql.ErrNoRows)
			} else {
				q.WillReturnRows(sqlmock.NewRows([]string{"session_id"}).AddRow(int64(42)))
			}
			id, err := r.UpdateSession(context.Background(), session, "old")
			if tc.missing {
				if err != authFail.GrpcInvalidRefreshToken {
					t.Fatalf("expected invalid refresh, got %v", err)
				}
			} else if err != nil || id != 42 {
				t.Fatalf("rotation lost stable ID %d %v", id, err)
			}
		})
	}
}
func TestCancelDeletionHonorsDeadlineUnderLock(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "expired"}[expired], func(t *testing.T) {
			r, m := mockRepository(t)
			id := uuid.New()
			deadline := time.Now().Add(time.Hour)
			if expired {
				deadline = time.Now().Add(-time.Hour)
			}
			m.ExpectBegin()
			m.ExpectQuery(`SELECT blocked FROM users .* FOR UPDATE`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"blocked"}).AddRow(false))
			m.ExpectQuery(`SELECT user_id,with_shared_data,deletion_timestamp .* FOR UPDATE`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"user_id", "with_shared_data", "deletion_timestamp"}).AddRow(id, true, deadline))
			if expired {
				m.ExpectRollback()
			} else {
				m.ExpectExec(`DELETE FROM delete_profile_requests`).WithArgs(id).WillReturnResult(sqlmock.NewResult(0, 1))
				m.ExpectCommit()
			}
			err := r.CancelProfileDeletion(context.Background(), id)
			if expired {
				if err != authFail.GrpcDeletionExpired {
					t.Fatalf("expired cancellation: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestDeletionPolicyUpdatePreservesDeadline(t *testing.T) {
	r, m := mockRepository(t)
	id := uuid.New()
	deadline := time.Now().Add(time.Hour)
	m.ExpectBegin()
	m.ExpectQuery(`SELECT blocked FROM users .* FOR UPDATE`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"blocked"}).AddRow(false))
	m.ExpectQuery(`SELECT user_id,with_shared_data,deletion_timestamp .* FOR UPDATE`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"user_id", "with_shared_data", "deletion_timestamp"}).AddRow(id, false, deadline))
	m.ExpectExec(`UPDATE delete_profile_requests SET with_shared_data=\$2 WHERE user_id=\$1`).WithArgs(id, true).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	result, err := r.UpdateProfileDeletion(context.Background(), id, true)
	if err != nil || !result.Timestamp.Equal(deadline) || !result.WithSharedData {
		t.Fatalf("policy changed deadline: %+v %v", result, err)
	}
}
func TestDeletionWorkerDoesNotDeleteAfterCancellation(t *testing.T) {
	r, m := mockRepository(t)
	id := uuid.New()
	m.ExpectBegin()
	m.ExpectQuery(`SELECT user_id FROM users .* FOR UPDATE`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(id))
	m.ExpectQuery(`SELECT with_shared_data,deletion_timestamp .* FOR UPDATE`).WithArgs(id).WillReturnError(sql.ErrNoRows)
	m.ExpectRollback()
	msg, err := r.DeleteUser(context.Background(), id, true)
	if err != nil || msg != nil {
		t.Fatalf("cancelled deletion should not publish/delete: %v %v", msg, err)
	}
}
func expectEmailProof(m sqlmock.Sqlmock, id uuid.UUID, token, stage string) {
	m.ExpectBegin()
	m.ExpectQuery(`SELECT user_id FROM email_bindings`).WithArgs(tokenHash(token)).WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(id))
	m.ExpectQuery(`SELECT email,blocked FROM users .* FOR UPDATE`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"email", "blocked"}).AddRow("old@example.com", false))
	purpose := "change"
	if stage == "verify" {
		purpose = "verify"
	}
	m.ExpectQuery(`SELECT purpose,stage,old_email,email,password_hash,expires_at .* FOR UPDATE`).WithArgs(tokenHash(token)).WillReturnRows(sqlmock.NewRows([]string{"purpose", "stage", "old_email", "email", "password_hash", "expires_at"}).AddRow(purpose, stage, "old@example.com", "new@example.com", nil, time.Now().Add(time.Hour)))
	m.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM delete_profile_requests`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
}
func TestOldEmailConfirmationQueuesNewProofWithoutChangingAddress(t *testing.T) {
	r, m := mockRepository(t)
	id := uuid.New()
	expectEmailProof(m, id, "old-token", "old")
	m.ExpectExec(`UPDATE email_bindings SET token_hash=\$2,stage='new',expires_at=\$3`).WithArgs(tokenHash("old-token"), sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec(`DELETE FROM email_deliveries WHERE user_id=\$1 AND purpose=\$2`).WithArgs(id, "change").WillReturnResult(sqlmock.NewResult(0, 0))
	m.ExpectExec(`INSERT INTO email_deliveries`).WithArgs(id, "new@example.com", sqlmock.AnyArg(), "https://example.com?token=%s", "change", "new", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	m.ExpectCommit()
	result, err := r.ConfirmEmailBinding(context.Background(), "old-token", "https://example.com?token=%s")
	if err != nil || result.Status != "pendingNewEmail" || result.Purpose != "change" {
		t.Fatalf("unexpected transition %+v %v", result, err)
	}
}
func TestNewEmailProofChangesAddressAndInvalidatesResetTokens(t *testing.T) {
	r, m := mockRepository(t)
	id := uuid.New()
	expectEmailProof(m, id, "new-token", "new")
	m.ExpectExec(`UPDATE users SET email=\$2 WHERE user_id=\$1`).WithArgs(id, "new@example.com").WillReturnResult(sqlmock.NewResult(0, 1))
	for _, table := range []string{"email_bindings", "activation_codes", "email_deliveries", "password_resets"} {
		m.ExpectExec(`DELETE FROM ` + table + ` WHERE user_id=\$1`).WithArgs(id).WillReturnResult(sqlmock.NewResult(0, 1))
	}
	m.ExpectCommit()
	result, err := r.ConfirmEmailBinding(context.Background(), "new-token", "https://example.com?token=%s")
	if err != nil || result.Status != "changed" {
		t.Fatalf("unexpected transition %+v %v", result, err)
	}
}
func TestConsumedEmailProofDoesNotRepeatSideEffects(t *testing.T) {
	r, m := mockRepository(t)
	m.ExpectBegin()
	m.ExpectQuery(`SELECT user_id FROM email_bindings`).WithArgs(tokenHash("consumed")).WillReturnError(sql.ErrNoRows)
	m.ExpectRollback()
	_, err := r.ConfirmEmailBinding(context.Background(), "consumed", "pattern")
	if err != authFail.GrpcInvalidActivationCode {
		t.Fatalf("expected invalid proof: %v", err)
	}
}
func TestEmailTransitionRollsBackWhenDeliveryCannotBeQueued(t *testing.T) {
	r, m := mockRepository(t)
	id := uuid.New()
	expectEmailProof(m, id, "old", "old")
	m.ExpectExec(`UPDATE email_bindings`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec(`DELETE FROM email_deliveries`).WillReturnResult(sqlmock.NewResult(0, 0))
	m.ExpectExec(`INSERT INTO email_deliveries`).WillReturnError(errors.New("database down"))
	m.ExpectRollback()
	_, err := r.ConfirmEmailBinding(context.Background(), "old", "pattern")
	if err != fail.GrpcUnknown {
		t.Fatal("queue failure should preserve old proof for retry")
	}
}
func TestOAuthStateIsBoundToProviderRedirectAndClient(t *testing.T) {
	r, m := mockRepository(t)
	m.ExpectExec(`DELETE FROM oauth_states WHERE token_hash=\$1 AND provider=\$2 AND redirect_uri=\$3 AND binding_hash=\$4 AND expires_at>NOW\(\)`).WithArgs(tokenHash("state"), "google", "https://example.com/callback", tokenHash("browser")).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := r.ConsumeOAuthState(context.Background(), "google", "state", "https://example.com/callback", "browser"); err != nil {
		t.Fatal(err)
	}
	m.ExpectExec(`DELETE FROM oauth_states`).WillReturnResult(sqlmock.NewResult(0, 0))
	if err := r.ConsumeOAuthState(context.Background(), "google", "state", "https://example.com/callback", "browser"); err != authFail.GrpcInvalidCode {
		t.Fatal("replay accepted")
	}
}
