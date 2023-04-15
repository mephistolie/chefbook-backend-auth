package entity

import "github.com/google/uuid"

type SignUpCredentials struct {
	Id       *uuid.UUID
	Email    string
	Password string
}

type CredentialsHash struct {
	Id           *uuid.UUID
	Email        string
	PasswordHash *string
}

type SignInCredentials struct {
	Email    *string
	Nickname *string
	Password string
}

type OAuthCredentials struct {
	Code  string
	State string
}

type UserIdentifiers struct {
	UserId   *uuid.UUID
	Email    *string
	Nickname *string
}
