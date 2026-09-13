package username

import (
	"context"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/assets"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	authlog "github.com/mephistolie/chefbook-backend-auth/internal/logging"
)

const (
	usernameRegex            = "^[a-zA-Z0-9_]+$"
	usernameStartLetterRegex = "^[a-zA-Z]$"
	usernameEndLetterRegex   = "^[a-zA-Z0-9]$"
)

type Validator struct {
	forbiddenUsernames []string
}

func NewValidator() *Validator {
	fileBytes, err := os.ReadFile(assets.ForbiddenUsernamesFilePath)
	if err != nil {
		authlog.Default.UsernameValidatorInitializationFailed(context.Background(), err)
	}
	return &Validator{
		forbiddenUsernames: strings.Split(string(fileBytes), "\n"),
	}
}

func (v *Validator) Validate(username string) error {
	usernameLen := len(username)
	if usernameLen < 5 {
		return authFail.GrpcUsernameTooShort
	}
	if usernameLen > 64 {
		return authFail.GrpcUsernameTooLong
	}
	if _, err := uuid.Parse(username); err == nil {
		return authFail.GrpcUsernameId
	}
	if match, err := regexp.MatchString(usernameStartLetterRegex, username[0:1]); err != nil || !match {
		return authFail.GrpcUsernameStartLetter
	}
	if match, err := regexp.MatchString(usernameEndLetterRegex, username[usernameLen-1:usernameLen]); err != nil || !match {
		return authFail.GrpcUsernameEndLetter
	}
	if match, err := regexp.MatchString(usernameRegex, username); err != nil || !match {
		return authFail.GrpcUsernameForbiddenSymbols
	}
	letterUsername := ""
	for _, char := range username {
		if unicode.IsLetter(char) {
			letterUsername += strings.ToLower(string(char))
		}
		if char == '1' {
			letterUsername += "i"
		}
	}
	for _, word := range v.forbiddenUsernames {
		if strings.Contains(letterUsername, word) {
			return authFail.GrpcUsernameForbiddenWord
		}
	}
	for i, _ := range username {
		if i > 0 && username[i] == '_' && username[i-1] == '_' {
			return authFail.GrpcUsernameDoubleUnderscore
		}
	}
	return nil
}
