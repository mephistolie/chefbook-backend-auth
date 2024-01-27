package postgres

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"time"
)

func (r *Repository) CreateSession(session entity.SessionInput) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (user_id, refresh_token, ip, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, sessionsTable)

	if _, err := r.db.Exec(query, session.UserId, session.RefreshToken, session.Ip, session.UserAgent,
		session.ExpiresAt); err != nil {
		log.Error("error while creating session: ", err)
		return fail.GrpcUnknown
	}
	return nil
}

func (r *Repository) GetSessions(userId uuid.UUID) []entity.SessionRawInfo {
	var sessions []entity.SessionRawInfo

	query := fmt.Sprintf(`
		SELECT session_id, user_id, ip, user_agent, last_access
		FROM %s
		WHERE user_id=$1
	`, sessionsTable)

	rows, err := r.db.Query(query, userId)
	if err != nil {
		log.Errorf("unable to get user %s sessions: %s", userId, err)
		return []entity.SessionRawInfo{}
	}

	for rows.Next() {
		var session entity.SessionRawInfo
		err = rows.Scan(&session.SessionId, &session.UserId, &session.Ip, &session.UserAgent, &session.AccessTime)
		if err != nil {
			log.Errorf("unable to parse user %s session: %s", userId, err)
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions
}

func (r *Repository) UpdateSession(session entity.SessionInput, oldRefreshToken string) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET refresh_token=$1, ip=$2, user_agent=$3, last_access=$4, expires_at=$5
		WHERE refresh_token=$6
	`, sessionsTable)

	if _, err := r.db.Exec(query, session.RefreshToken, session.Ip, session.UserAgent, time.Now(), session.ExpiresAt,
		oldRefreshToken); err != nil {
		log.Debugf("unable to update session for user %s: %s", session.UserId, err)
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) DeleteSession(refreshToken string) error {
	var id = ""

	deleteSessionQuery := fmt.Sprintf(`
		DELETE FROM %s
		WHERE refresh_token=$1
		RETURNING session_id
	`, sessionsTable)

	row := r.db.QueryRow(deleteSessionQuery, refreshToken)
	if err := row.Scan(&id); err != nil || id == "" {
		log.Warn("unable to delete session: ", err)
		return authFail.GrpcSessionNotFound
	}

	return nil
}

func (r *Repository) DeleteSessions(userId uuid.UUID, sessionIds []int64) {
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1 AND session_id=ANY($2)
	`, sessionsTable)

	if _, err := r.db.Exec(query, userId, sessionIds); err != nil {
		log.Warnf("unable to delete sessions for user %s: %s", userId, err)
	}
}

func (r *Repository) DeleteAllSessions(userId uuid.UUID) {
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE user_id=$1
	`, sessionsTable)

	if _, err := r.db.Exec(query, userId); err != nil {
		log.Warnf("unable to delete sessions for user %s: %s", userId, err)
	}
}

func (r *Repository) DeleteOutdatedSessions(userId uuid.UUID, sessionsThreshold int) {
	query := fmt.Sprintf(`
		DELETE FROM %[1]v
		WHERE session_id NOT IN
		(
			SELECT session_id
			FROM %[1]v
			WHERE user_id=$1
			ORDER BY created_at DESC
			LIMIT %[2]v
		)
	`, sessionsTable, sessionsThreshold)

	if _, err := r.db.Exec(query, userId); err != nil {
		log.Warnf("unable to delete sessions for user %s: %s", userId, err)
	}
}
