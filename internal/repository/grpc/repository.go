package grpc

import "github.com/mephistolie/chefbook-backend-auth/internal/config"

type Repository struct {
	Subscription *Subscription
}

func NewRepository(cfg *config.Config) (*Repository, error) {
	subscriptionService, err := NewSubscription(*cfg.SubscriptionService.Addr)
	if err != nil {
		return nil, err
	}

	return &Repository{
		Subscription: subscriptionService,
	}, nil
}

func (r *Repository) Stop() error {
	_ = r.Subscription.Conn.Close()
	return nil
}
