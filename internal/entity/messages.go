package entity

import "github.com/google/uuid"

type MessageData struct {
	Id       uuid.UUID
	Exchange string
	Type     string
	Body     []byte
}
