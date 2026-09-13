package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
)

func (r *Repository) createOutboxMsg(ctx context.Context, msg *entity.MessageData, tx *sql.Tx) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (message_id, exchange, type, body)
		VALUES ($1, $2, $3, $4)
	`, outboxTable)

	if _, err := tx.ExecContext(ctx, query, msg.Id, msg.Exchange, msg.Type, msg.Body); err != nil {
		authlog.Default.PostgresOperationFailed(ctx, authlog.PostgresOperationData{
			Operation: "CreateOutboxMessage",
			MessageID: msg.Id.String(),
			Entity:    "outbox_message",
		}, err)
		return errorWithTransactionRollback(tx, fail.GrpcUnknown)
	}

	return nil
}

func (r *Repository) GetPendingMessages(ctx context.Context) ([]*entity.MessageData, error) {
	var msgs []*entity.MessageData

	query := fmt.Sprintf(`
		SELECT message_id, exchange, type, body
		FROM %s
	`, outboxTable)

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var msg entity.MessageData
		err := rows.Scan(&msg.Id, &msg.Exchange, &msg.Type, &msg.Body)
		if err != nil {
			authlog.Default.PostgresOperationWarned(ctx, authlog.PostgresOperationData{
				Operation: "GetPendingMessages",
				Entity:    "outbox_message",
			}, err)
			continue
		}
		msgs = append(msgs, &msg)
	}

	return msgs, nil
}

func (r *Repository) MarkMessageSent(ctx context.Context, messageId uuid.UUID) error {
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE message_id=$1
	`, outboxTable)

	_, err := r.db.ExecContext(ctx, query, messageId)
	if err != nil {
		authlog.Default.PostgresOperationWarned(ctx, authlog.PostgresOperationData{
			Operation: "MarkMessageSent",
			MessageID: messageId.String(),
			Entity:    "outbox_message",
		}, err)
	}
	return err
}
