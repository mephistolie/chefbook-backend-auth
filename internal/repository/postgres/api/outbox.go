package api

import (
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
)

type Outbox interface {
	GetPendingMessages() ([]*entity.MessageData, error)
	MarkMessageSent(messageId uuid.UUID) error
}
