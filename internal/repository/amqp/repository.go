package amqp

import (
	"fmt"
	api "github.com/mephistolie/chefbook-backend-auth/api/mq"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	outboxApi "github.com/mephistolie/chefbook-backend-auth/internal/repository/postgres/api"
	amqp "github.com/wagslane/go-rabbitmq"
	"time"
)

type Repository struct {
	conn              *amqp.Conn
	publisherProfiles *amqp.Publisher
	outbox            outboxApi.Outbox
}

func NewRepository(cfg config.Amqp, outbox outboxApi.Outbox) (*Repository, error) {
	url := fmt.Sprintf("amqp://%s:%s@%s:%d/%s", *cfg.User, *cfg.Password, *cfg.Host, *cfg.Port, *cfg.VHost)
	conn, err := amqp.NewConn(url)
	if err != nil {
		return nil, err
	}

	return &Repository{
		conn:   conn,
		outbox: outbox,
	}, nil
}

func (r *Repository) Start() error {
	var err error = nil
	r.publisherProfiles, err = amqp.NewPublisher(
		r.conn,
		amqp.WithPublisherOptionsExchangeName(api.ExchangeProfiles),
		amqp.WithPublisherOptionsExchangeKind("fanout"),
		amqp.WithPublisherOptionsExchangeDurable,
		amqp.WithPublisherOptionsExchangeDeclare,
	)
	if err != nil {
		return err
	}

	go r.observeOutbox()

	return nil
}

func (r *Repository) observeOutbox() {
	for {
		fails := 0
		if msgs, err := r.outbox.GetPendingMessages(); err == nil {
			for _, msg := range msgs {
				if err = r.PublishProfilesMessage(msg); err != nil {
					fails += 1
					if fails >= 5 {
						break
					}
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
}

func (r *Repository) Stop() error {
	r.publisherProfiles.Close()
	return r.conn.Close()
}
