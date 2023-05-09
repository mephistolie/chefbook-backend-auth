package rabbitmq

import (
	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	outboxApi "github.com/mephistolie/chefbook-backend-auth/internal/repository/postgres/api"
	"github.com/mephistolie/chefbook-backend-common/log"
	amqp "github.com/wagslane/go-rabbitmq"
	"time"
)

func (r *Repository) sendMessages() {
	for {
		if msgs, err := r.outbox.GetPendingMessages(); err == nil {
			fails := 0
			for _, msg := range msgs {
				_ = r.outbox.SetMessageStatus(msg.EventId, outboxApi.StatusProcessing)
				if err = r.publishProfilesMessage(msg); err != nil {
					fails += 1
					if fails >= 5 {
						break
					}
					_ = r.outbox.SetMessageStatus(msg.EventId, outboxApi.StatusPending)
				} else {
					_ = r.outbox.SetMessageStatus(msg.EventId, outboxApi.StatusSent)
				}
			}
		}
		time.Sleep(1 * time.Minute)
	}
}

func (r *Repository) PublishProfileMessage(msg entity.MessageData) {
	_ = r.outbox.SetMessageStatus(msg.EventId, outboxApi.StatusPending)
	_ = r.publishProfilesMessage(msg)
	_ = r.outbox.SetMessageStatus(msg.EventId, outboxApi.StatusSent)
}

func (r *Repository) publishProfilesMessage(msg entity.MessageData) error {
	err := r.pubProfiles.Publish(
		msg.Body,
		[]string{""},
		amqp.WithPublishOptionsExchange(api.ExchangeProfiles),
		amqp.WithPublishOptionsMessageID(msg.EventId.String()),
		amqp.WithPublishOptionsPersistentDelivery,
		amqp.WithPublishOptionsContentType("application/json"),
		amqp.WithPublishOptionsType(msg.Type),
		amqp.WithPublishOptionsAppID(api.AppId),
	)
	if err == nil {
		log.Infof("message %s sent successfully", msg.EventId)
	} else {
		log.Warnf("unable to send message %s: %s", msg.EventId, err)
	}
	return err
}
