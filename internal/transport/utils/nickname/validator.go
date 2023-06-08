package nickname

import (
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/assets"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-common/log"
	"os"
	"regexp"
	"strings"
	"unicode"
)

const (
	nicknameRegex            = "^[a-zA-Z0-9_]+$"
	nicknameStartLetterRegex = "^[a-zA-Z]$"
	nicknameEndLetterRegex   = "^[a-zA-Z0-9]$"
)

type Validator struct {
	forbiddenNicknames []string
}

func NewValidator() *Validator {
	fileBytes, err := os.ReadFile(assets.ForbiddenNicknamesFilePath)
	if err != nil {
		log.Error("error during nickname validator initialization: ", err)
	}
	return &Validator{
		forbiddenNicknames: strings.Split(string(fileBytes), "\n"),
	}
}

func (v *Validator) Validate(nickname string) error {
	nicknameLen := len(nickname)
	if nicknameLen < 5 {
		return authFail.GrpcNicknameTooShort
	}
	if nicknameLen > 64 {
		return authFail.GrpcNicknameTooLong
	}
	if _, err := uuid.Parse(nickname); err == nil {
		return authFail.GrpcNicknameId
	}
	if match, err := regexp.MatchString(nicknameStartLetterRegex, nickname[0:1]); err != nil || !match {
		return authFail.GrpcNicknameStartLetter
	}
	if match, err := regexp.MatchString(nicknameEndLetterRegex, nickname[nicknameLen-1:nicknameLen]); err != nil || !match {
		return authFail.GrpcNicknameEndLetter
	}
	if match, err := regexp.MatchString(nicknameRegex, nickname); err != nil || !match {
		return authFail.GrpcNicknameForbiddenSymbols
	}
	letterNickname := ""
	for _, char := range nickname {
		if unicode.IsLetter(char) {
			letterNickname += strings.ToLower(string(char))
		}
		if char == '1' {
			letterNickname += "i"
		}
	}
	for _, word := range v.forbiddenNicknames {
		if strings.Contains(letterNickname, word) {
			return authFail.GrpcNicknameForbiddenWord
		}
	}
	for i, _ := range nickname {
		if i > 0 && nickname[i] == '_' && nickname[i-1] == '_' {
			return authFail.GrpcNicknameDoubleUnderscore
		}
	}
	return nil
}
