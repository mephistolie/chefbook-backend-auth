package entity

import (
	"github.com/google/uuid"
	"time"
)

type ClientData struct {
	Ip        string
	UserAgent string
}

type SessionInput struct {
	UserId       uuid.UUID
	RefreshToken string
	Ip           string
	UserAgent    string
	ExpiresAt    time.Time
}

type SessionRawInfo struct {
	SessionId  int64
	UserId     uuid.UUID
	Ip         string
	UserAgent  string
	AccessTime time.Time
}

type SessionInfo struct {
	SessionId   int64
	UserId      uuid.UUID
	Ip          string
	AccessPoint string
	Mobile      bool
	AccessTime  time.Time
	Location    string
}
