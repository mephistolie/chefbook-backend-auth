package entity

import (
	"github.com/google/uuid"
	"time"
)

type Tokens struct {
	SessionId           int64
	DeleteSharedData    bool
	ProfileId           uuid.UUID
	AccessToken         string
	RefreshToken        string
	ExpirationTimestamp time.Time
	DeletionTimestamp   *time.Time
}
