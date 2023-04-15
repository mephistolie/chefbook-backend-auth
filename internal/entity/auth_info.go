package entity

import (
	"github.com/google/uuid"
	"time"
)

type AuthInfo struct {
	Id                    uuid.UUID
	Email                 string
	Nickname              *string
	PasswordHash          string
	Role                  string
	RegistrationTimestamp time.Time
	IsActivated           bool
	IsBlocked             bool
	OAuth                 OAuth
}

type OAuth struct {
	GoogleId *string
	VkId     *int64
}
