package api

import (
	"context"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
)

type Outbox interface {
	GetPendingMessages(ctx context.Context) ([]*entity.MessageData, error)
	MarkMessageSent(ctx context.Context, messageId uuid.UUID) error
}
