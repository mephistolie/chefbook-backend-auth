package postgres

import (
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) createOutboxMsg(msg *entity.MessageData, tx *sql.Tx) error {
	query := fmt.Sprintf(`
			INSERT INTO %s (message_id, exchange, type, body)
			VALUES ($1, $2, $3, $4)
		`, outboxTable)

	if _, err := tx.Exec(query, msg.Id, msg.Exchange, msg.Type, msg.Body); err != nil {
		log.Error("unable to add message to outbox: ", err)
		return errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	return nil
}

func (r *Repository) GetPendingMessages() ([]*entity.MessageData, error) {
	var msgs []*entity.MessageData

	query := fmt.Sprintf(`
			SELECT message_id, exchange, type, body
			FROM %s
		`, outboxTable)

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var msg entity.MessageData
		err := rows.Scan(&msg.Id, &msg.Exchange, &msg.Type, &msg.Body)
		if err != nil {
			log.Warn("unable to get scan message row: ", err)
			continue
		}
		msgs = append(msgs, &msg)
	}

	return msgs, nil
}

func (r *Repository) MarkMessageSent(messageId uuid.UUID) error {
	query := fmt.Sprintf(`
			DELETE FROM %s
			WHERE message_id=$1
		`, outboxTable)

	_, err := r.db.Exec(query, messageId)
	if err != nil {
		log.Warnf("unable to update status for message %s: %s", messageId, err)
	}
	return err
}
