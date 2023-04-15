package entity

import "github.com/google/uuid"

type VerificationEmailInput struct {
	Email            string
	Name             string
	VerificationCode uuid.UUID
	Domain           string
}
