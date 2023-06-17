package entity

import (
	"github.com/google/uuid"
	"time"
)

type DeleteProfileRequest struct {
	UserId         uuid.UUID
	WithSharedData bool
	Timestamp      time.Time
}
