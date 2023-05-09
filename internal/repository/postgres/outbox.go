package postgres

import (
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-auth/internal/repository/postgres/api"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) createOutboxMsg(msg entity.MessageData, tx *sql.Tx) error {
	query := fmt.Sprintf(`
			INSERT INTO %s (event_id, exchange, type, body)
			VALUES ($1, $2, $3, $4)
		`, outboxTable)

	if _, err := tx.Exec(query, msg.EventId, msg.Exchange, msg.Type, msg.Body); err != nil {
		log.Error("unable to add user created message to outbox: ", err)
		if err := tx.Rollback(); err != nil {
			log.Error("unable to rollback transaction: ", err)
		}
		return fail.GrpcUnknown
	}

	return nil
}

func (r *Repository) GetPendingMessages() ([]entity.MessageData, error) {
	var msgs []entity.MessageData

	query := fmt.Sprintf(`
			SELECT event_id, exchange, type, body
			FROM %s
			WHERE status='%s'
		`, outboxTable, api.StatusPending)

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var msg entity.MessageData
		err := rows.Scan(&msg.EventId, &msg.Exchange, &msg.Type, &msg.Body)
		if err != nil {
			log.Warn("unable to get scan message row: ", err)
			continue
		}
		msgs = append(msgs, msg)
	}

	return msgs, nil
}

func (r *Repository) SetMessageStatus(eventId uuid.UUID, status string) error {
	query := fmt.Sprintf(`
			UPDATE %s
			SET status=$1
			WHERE event_id=$2
		`, outboxTable)

	_, err := r.db.Exec(query, status, eventId)
	if err != nil {
		log.Warnf("unable to update status for message %s: %s", eventId, err)
	}
	return err
}
