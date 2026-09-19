package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) CreateSession(ctx context.Context, session entity.SessionInput) (int64, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, `INSERT INTO sessions (user_id, refresh_token, ip, user_agent, expires_at)
 VALUES ($1,$2,$3,$4,$5) RETURNING session_id`, session.UserId, session.RefreshToken, session.Ip, session.UserAgent, session.ExpiresAt).Scan(&id)
	if err != nil {
		return 0, fail.GrpcUnknown
	}
	return id, nil
}

func (r *Repository) GetSessions(ctx context.Context, userId uuid.UUID) ([]entity.SessionRawInfo, error) {
	var sessions []entity.SessionRawInfo

	query := fmt.Sprintf(`
		SELECT session_id, user_id, ip, user_agent, last_access
		FROM %s
		WHERE user_id=$1 AND expires_at>NOW()
	`, sessionsTable)

	rows, err := r.db.QueryContext(ctx, query, userId)
	if err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "GetSessions",
			UserID:    userId.String(),
			Entity:    "session",
		}, err)
		return nil, fail.GrpcUnknown
	}

	defer rows.Close()
	for rows.Next() {
		var session entity.SessionRawInfo
		err = rows.Scan(&session.SessionId, &session.UserId, &session.Ip, &session.UserAgent, &session.AccessTime)
		if err != nil {
			authlog.Default.PostgresRowScanFailed(ctx, authlog.PostgresOperationData{
				Operation: "GetSessions",
				UserID:    userId.String(),
				Entity:    "session",
			}, err)
			return nil, fail.GrpcUnknown
		}
		sessions = append(sessions, session)
	}

	if rows.Err() != nil {
		return nil, fail.GrpcUnknown
	}
	return sessions, nil
}

func (r *Repository) UpdateSession(ctx context.Context, session entity.SessionInput, oldRefreshToken string) (int64, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, `UPDATE sessions SET refresh_token=$1,ip=$2,user_agent=$3,last_access=NOW(),expires_at=$4
 WHERE refresh_token=$5 AND expires_at>NOW() RETURNING session_id`, session.RefreshToken, session.Ip, session.UserAgent, session.ExpiresAt, oldRefreshToken).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, authFail.GrpcInvalidRefreshToken
	}
	if err != nil {
		return 0, fail.GrpcUnknown
	}
	return id, nil
}

func (r *Repository) DeleteSession(ctx context.Context, refreshToken string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE refresh_token=$1`, refreshToken)
	if err != nil {
		return fail.GrpcUnknown
	}
	return nil
}

func (r *Repository) DeleteSessions(ctx context.Context, userId uuid.UUID, sessionIds []int64) error {
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
		return fail.GrpcUnknown
	}
	return nil
}

func (r *Repository) DeleteAllSessions(ctx context.Context, userId uuid.UUID) error {
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
		return fail.GrpcUnknown
	}
	return nil
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
