package amqp

import (
	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-common/log"
	amqp "github.com/wagslane/go-rabbitmq"
)

func (r *Repository) PublishProfilesMessage(msg *entity.MessageData) error {
	log.Infof("publishing message %s with type %s to exchange %s...", msg.Id, msg.Type, api.ExchangeProfiles)
	err := r.publisherProfiles.Publish(
		msg.Body,
		[]string{""},
		amqp.WithPublishOptionsExchange(api.ExchangeProfiles),
		amqp.WithPublishOptionsMessageID(msg.Id.String()),
		amqp.WithPublishOptionsPersistentDelivery,
		amqp.WithPublishOptionsContentType("application/json"),
		amqp.WithPublishOptionsType(msg.Type),
		amqp.WithPublishOptionsAppID(api.AppId),
	)
	if err == nil {
		log.Infof("message %s with type %s sent successfully", msg.Id, msg.Type)
	} else {
		log.Warnf("unable to send message %s with type %s: %s", msg.Id, msg.Type, err)
	}

	if err == nil {
		_ = r.outbox.MarkMessageSent(msg.Id)
	}

	return err
}
