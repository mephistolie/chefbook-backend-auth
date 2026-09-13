package amqp

import (
	"context"

	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
	amqp "github.com/wagslane/go-rabbitmq"
)

func (r *Repository) PublishProfilesMessage(ctx context.Context, msg *entity.MessageData) error {
	eventData := authlog.MessageData{
		MessageID: msg.Id.String(),
		Type:      msg.Type,
		Exchange:  api.ExchangeProfiles,
	}
	authlog.Default.MessagePublishStarted(ctx, eventData)
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
		authlog.Default.MessagePublished(ctx, eventData)
	} else {
		authlog.Default.MessagePublishFailed(ctx, eventData, err)
	}

	if err == nil {
		_ = r.outbox.MarkMessageSent(ctx, msg.Id)
	}

	return err
}
