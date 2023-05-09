package api

import (
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
)

const StatusPending = "pending"
const StatusProcessing = "processing"
const StatusSent = "sent"

type Outbox interface {
	GetPendingMessages() ([]entity.MessageData, error)
	SetMessageStatus(eventId uuid.UUID, status string) error
}
