package grpc

import (
	api "github.com/mephistolie/chefbook-backend-subscription/api/proto/implementation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Subscription struct {
	api.SubscriptionServiceClient
	Conn *grpc.ClientConn
}

func NewSubscription(addr string) (*Subscription, error) {
	opts := grpc.WithTransportCredentials(insecure.NewCredentials())
	conn, err := grpc.Dial(addr, opts)
	if err != nil {
		return nil, err
	}
	return &Subscription{
		SubscriptionServiceClient: api.NewSubscriptionServiceClient(conn),
		Conn:                      conn,
	}, nil
}
