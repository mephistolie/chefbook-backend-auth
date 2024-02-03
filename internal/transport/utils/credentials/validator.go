package credentials

import (
	"github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"net/mail"
	"regexp"
	"unicode"
)

const (
	passwordRegex = "^[a-zA-Z0-9_!@#$%^&*]+$"
)

func ValidateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	return err
}

func ValidatePassword(password string) error {
	lower := false
	upper := false
	number := false
	if len(password) < 8 {
		return fail.GrpcPasswordTooShort
	}
	if len(password) > 64 {
		return fail.GrpcPasswordTooLong
	}
	if match, err := regexp.MatchString(passwordRegex, password); err != nil || !match {
		return fail.GrpcPasswordForbiddenSymbols
	}
	for _, c := range password {
		switch {
		case unicode.IsLower(c):
			lower = true
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsNumber(c):
			number = true
		default:
		}
		if lower && upper && number {
			break
		}
	}
	if !lower {
		return fail.GrpcPasswordNoLower
	}
	if !upper {
		return fail.GrpcPasswordNoUpper
	}
	if !number {
		return fail.GrpcPasswordNoNumber
	}
	return nil
}
