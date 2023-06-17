package entity

import "time"

type Tokens struct {
	AccessToken         string
	RefreshToken        string
	ExpirationTimestamp time.Time
	DeletionTimestamp   *time.Time
}
