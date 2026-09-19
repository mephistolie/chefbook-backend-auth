// Package outbox delivers transactionally queued events with broker confirms.
package outbox

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

type Worker struct {
	DB  *sql.DB
	URL string
}

// Run reconnects after channel/connection errors; no event is removed before a
// mandatory, persistent publish was routed and acknowledged by the broker.
// Delivery is at least once: crash after confirmation before commit may duplicate.
func (w Worker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		_ = w.runConnection(ctx)
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (w Worker) runConnection(ctx context.Context) error {
	conn, err := amqp.DialConfig(w.URL, amqp.Config{Dial: amqp.DefaultDial(10 * time.Second)})
	if err != nil {
		return err
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()
	if err = ch.ExchangeDeclare("auth.profiles", "fanout", true, false, false, false, nil); err != nil {
		return err
	}
	if err = ch.ExchangeDeclare("mail", "direct", true, false, false, false, nil); err != nil {
		return err
	}
	if err = ch.Confirm(false); err != nil {
		return err
	}
	returns := ch.NotifyReturn(make(chan amqp.Return, 1))
	for ctx.Err() == nil {
		delivered, err := w.one(ctx, ch, returns)
		if err != nil {
			return err
		}
		if !delivered {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return ctx.Err()
}
func (w Worker) one(ctx context.Context, ch *amqp.Channel, returns <-chan amqp.Return) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := w.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var id uuid.UUID
	var exchange, kind string
	var body []byte
	err = tx.QueryRowContext(ctx, `SELECT message_id,exchange,type,body FROM outbox ORDER BY creation_timestamp,message_id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &exchange, &kind, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	routing := ""
	if exchange == "mail" {
		routing = "mail.send"
	} else if exchange != "auth.profiles" {
		return false, errors.New("unsupported outbox exchange")
	}
	confirmation, err := ch.PublishWithDeferredConfirmWithContext(ctx, exchange, routing, true, false, amqp.Publishing{ContentType: "application/json", DeliveryMode: amqp.Persistent, MessageId: id.String(), Type: kind, AppId: "auth-service", Body: body, Timestamp: time.Now()})
	if err != nil {
		return false, err
	}
	if confirmation == nil {
		return false, errors.New("missing publisher confirmation")
	}
	ack, err := confirmation.WaitContext(ctx)
	if err != nil {
		return false, err
	}
	if !ack {
		return false, errors.New("broker rejected event")
	}
	// AMQP sends basic.return before basic.ack; the library dispatches in order.
	select {
	case <-returns:
		return false, errors.New("event has no bound consumer")
	default:
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM outbox WHERE message_id=$1`, id); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
