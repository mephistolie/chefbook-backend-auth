package entity

import (
	"github.com/google/uuid"
	"time"
)

type EmailBinding struct {
	UserId                                              uuid.UUID
	Purpose, Stage, OldEmail, Email, Token, LinkPattern string
	PasswordHash                                        *string
	ExpiresAt                                           time.Time
}
type EmailConfirmation struct{ Purpose, Status string }
type EmailDelivery struct {
	UserId                                    uuid.UUID
	Email, Token, LinkPattern, Purpose, Stage string
}
