package dto

import (
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"time"
)

type AuthInfo struct {
	Id                    uuid.UUID  `db:"user_id"`
	Email                 string     `db:"email"`
	Nickname              *string    `db:"nickname"`
	PasswordHash          *string    `db:"password"`
	Role                  string     `db:"role"`
	RegistrationTimestamp time.Time  `db:"registered"`
	IsActivated           bool       `db:"activated"`
	IsBlocked             bool       `db:"blocked"`
	DeletionTimestamp     *time.Time `db:"deletion_timestamp"`
	GoogleId              *string    `db:"google_id"`
	VkId                  *int64     `db:"vk_id"`
}

func (p *AuthInfo) Entity() entity.AuthInfo {
	passwordHash := ""
	if p.PasswordHash != nil {
		passwordHash = *p.PasswordHash
	}
	return entity.AuthInfo{
		Id:                    p.Id,
		Email:                 p.Email,
		Nickname:              p.Nickname,
		PasswordHash:          passwordHash,
		Role:                  p.Role,
		RegistrationTimestamp: p.RegistrationTimestamp,
		IsActivated:           p.IsActivated,
		IsBlocked:             p.IsBlocked,
		DeletionTimestamp:     p.DeletionTimestamp,
		OAuth: entity.OAuth{
			GoogleId: p.GoogleId,
			VkId:     p.VkId,
		},
	}
}
