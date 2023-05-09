package rabbitmq

import (
	"fmt"
	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	outboxApi "github.com/mephistolie/chefbook-backend-auth/internal/repository/postgres/api"
	amqp "github.com/wagslane/go-rabbitmq"
)

type Repository struct {
	conn        *amqp.Conn
	pubProfiles *amqp.Publisher
	outbox      outboxApi.Outbox
}

func NewRepository(cfg config.Amqp, outbox outboxApi.Outbox) (*Repository, error) {
	url := fmt.Sprintf("amqp://%s:%s@%s:%d/%s", *cfg.User, *cfg.Password, *cfg.Host, *cfg.Port, *cfg.VHost)
	conn, err := amqp.NewConn(url)
	if err != nil {
		return nil, err
	}

	pubProfiles, err := amqp.NewPublisher(
		conn,
		amqp.WithPublisherOptionsExchangeName(api.ExchangeProfiles),
		amqp.WithPublisherOptionsExchangeKind("fanout"),
		amqp.WithPublisherOptionsExchangeDurable,
		amqp.WithPublisherOptionsExchangeDeclare,
	)
	if err != nil {
		return nil, err
	}

	mq := Repository{
		conn:        conn,
		pubProfiles: pubProfiles,
		outbox:      outbox,
	}
	go mq.sendMessages()

	return &mq, nil
}

func (r *Repository) Stop() error {
	r.pubProfiles.Close()
	return r.conn.Close()
}
