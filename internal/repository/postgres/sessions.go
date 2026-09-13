package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) CreateSession(ctx context.Context, session entity.SessionInput) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (user_id, refresh_token, ip, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, sessionsTable)

	if _, err := r.db.ExecContext(ctx, query, session.UserId, session.RefreshToken, session.Ip, session.UserAgent,
		session.ExpiresAt); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "CreateSession",
			UserID:    session.UserId.String(),
			Entity:    "session",
		}, err)
		return fail.GrpcUnknown
	}
	return nil
}

func (r *Repository) GetSessions(ctx context.Context, userId uuid.UUID) []entity.SessionRawInfo {
	var sessions []entity.SessionRawInfo

	query := fmt.Sprintf(`
		SELECT session_id, user_id, ip, user_agent, last_access
		FROM %s
		WHERE user_id=$1
	`, sessionsTable)

	rows, err := r.db.QueryContext(ctx, query, userId)
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "GetSessions",
			UserID:    userId.String(),
			Entity:    "session",
		}, err)
		return []entity.SessionRawInfo{}
	}

	for rows.Next() {
		var session entity.SessionRawInfo
		err = rows.Scan(&session.SessionId, &session.UserId, &session.Ip, &session.UserAgent, &session.AccessTime)
		if err != nil {
			authlog.Default.PostgresRowScanFailed(ctx, authlog.PostgresOperationData{
				Operation: "GetSessions",
				UserID:    userId.String(),
				Entity:    "session",
			}, err)
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions
}

func (r *Repository) UpdateSession(ctx context.Context, session entity.SessionInput, oldRefreshToken string) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET refresh_token=$1, ip=$2, user_agent=$3, last_access=$4, expires_at=$5
		WHERE refresh_token=$6
	`, sessionsTable)

	if _, err := r.db.ExecContext(ctx, query, session.RefreshToken, session.Ip, session.UserAgent, time.Now(), session.ExpiresAt,
		oldRefreshToken); err != nil {
		authlog.Default.PostgresOperationWarned(ctx, authlog.PostgresOperationData{
			Operation: "UpdateSession",
			UserID:    session.UserId.String(),
			Entity:    "session",
		}, err)
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) DeleteSession(ctx context.Context, refreshToken string) error {
	var id = ""

	deleteSessionQuery := fmt.Sprintf(`
		DELETE FROM %s
		WHERE refresh_token=$1
		RETURNING session_id
	`, sessionsTable)

	row := r.db.QueryRowContext(ctx, deleteSessionQuery, refreshToken)
	if err := row.Scan(&id); err != nil || id == "" {
		authlog.Default.PostgresLookupWarned(ctx, authlog.PostgresOperationData{
			Operation: "DeleteSession",
			Entity:    "session",
		})
		return authFail.GrpcSessionNotFound
	}

	return nil
}

func (r *Repository) DeleteSessions(ctx context.Context, userId uuid.UUID, sessionIds []int64) {
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1 AND session_id=ANY($2)
	`, sessionsTable)

	if _, err := r.db.ExecContext(ctx, query, userId, sessionIds); err != nil {
		authlog.Default.PostgresOperationWarned(ctx, authlog.PostgresOperationData{
			Operation: "DeleteSessions",
			UserID:    userId.String(),
			Entity:    "session",
			Count:     len(sessionIds),
		}, err)
	}
}

func (r *Repository) DeleteAllSessions(ctx context.Context, userId uuid.UUID) {
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1
	`, sessionsTable)

	if _, err := r.db.ExecContext(ctx, query, userId); err != nil {
		authlog.Default.PostgresOperationWarned(ctx, authlog.PostgresOperationData{
			Operation: "DeleteAllSessions",
			UserID:    userId.String(),
			Entity:    "session",
		}, err)
	}
}

func (r *Repository) DeleteOutdatedSessions(ctx context.Context, userId uuid.UUID, sessionsThreshold int) {
	query := fmt.Sprintf(`
		DELETE FROM %[1]v
		WHERE user_id=$1 AND session_id NOT IN
		(
			SELECT session_id
			FROM %[1]v
			WHERE user_id=$1
			ORDER BY created_at DESC
			LIMIT %[2]v
		)
	`, sessionsTable, sessionsThreshold)

	if _, err := r.db.ExecContext(ctx, query, userId); err != nil {
		authlog.Default.PostgresOperationWarned(ctx, authlog.PostgresOperationData{
			Operation: "DeleteOutdatedSessions",
			UserID:    userId.String(),
			Entity:    "session",
			Count:     sessionsThreshold,
		}, err)
	}
}
