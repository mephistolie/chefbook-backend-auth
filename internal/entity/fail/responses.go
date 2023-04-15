package fail

import "github.com/mephistolie/chefbook-backend-common/responses/fail"

const (
	typeInvalidCredentials    = "invalid_credentials"
	typeProfileNotActivated   = "profile_not_activated"
	typeInvalidActivationCode = "invalid_activation_code"
	typeProfileExists         = "profile_exists"
	typeProfileBlocked        = "profile_blocked"
	typeNicknameOccupied      = "nickname_occupied"
	typeAccountOccupied       = "account_occupied"
	typeFewSignInMethods      = "few_sign_in_methods"
)

var (
	GrpcUnableCreateProfile = fail.CreateGrpcServer(fail.TypeUnknown, "unable to create profile")

	GrpcInvalidEmail             = fail.CreateGrpcClient(fail.TypeInvalidBody, "email is invalid")
	GrpcInvalidPassword          = fail.CreateGrpcClient(fail.TypeInvalidBody, "password is invalid")
	GrpcPasswordTooShort         = fail.CreateGrpcClient(fail.TypeInvalidBody, "password must contain at least 8 symbols")
	GrpcPasswordTooLong          = fail.CreateGrpcClient(fail.TypeInvalidBody, "password must contain maximum 64 symbols")
	GrpcPasswordForbiddenSymbols = fail.CreateGrpcClient(fail.TypeInvalidBody, "password contains forbidden symbols")
	GrpcPasswordNoLower          = fail.CreateGrpcClient(fail.TypeInvalidBody, "password must contain at least 1 lower letter")
	GrpcPasswordNoUpper          = fail.CreateGrpcClient(fail.TypeInvalidBody, "password must contain at least 1 upper letter")
	GrpcPasswordNoNumber         = fail.CreateGrpcClient(fail.TypeInvalidBody, "password must contain at least 1 number")

	GrpcUserAlreadyExists     = fail.CreateGrpcClient(typeProfileExists, "user with such email already exists")
	GrpcProfileNotActivated   = fail.CreateGrpcClient(typeProfileNotActivated, "profile not activated. check your email")
	GrpcInvalidActivationCode = fail.CreateGrpcClient(typeInvalidActivationCode, "invalid activation code")
	GrpcInvalidCredentials    = fail.CreateGrpcClient(typeInvalidCredentials, "invalid credentials")

	GrpcFewSignInMethods = fail.CreateGrpcClient(typeFewSignInMethods, "if you disable this sign in method, you'll not be able to sign in your profile")
	GrpcInvalidCode      = fail.CreateGrpcClient(fail.TypeInvalidBody, "code is invalid")
	GrpcAccountOccupied  = fail.CreateGrpcClient(typeAccountOccupied, "this OAuth profile already connected to different ChefBook Profile")
	GrpcEmailRequired    = fail.CreateGrpcClient(fail.TypeInvalidBody, "email access is required to complete registration")

	GrpcProfileIsBlocked = fail.CreateGrpcUnauthorized(typeProfileBlocked, "profile is blocked")
	GrpcSessionExpired   = fail.CreateGrpcUnauthorized(fail.TypeUnauthorized, "session expired")
	GrpcSessionNotFound  = fail.CreateGrpcUnauthorized(fail.TypeUnauthorized, "session not found")

	GrpcUserNotFound           = fail.CreateGrpcNotFound(fail.TypeNotFound, "user not found")
	GrpcActivationLinkNotFound = fail.CreateGrpcNotFound(fail.TypeNotFound, "activation link not found")

	GrpcInvalidResetPasswordCode = fail.CreateGrpcClient(fail.TypeInvalidBody, "invalid password reset code")

	GrpcNicknameTooShort         = fail.CreateGrpcClient(fail.TypeInvalidBody, "nickname must contain at least 5 symbols")
	GrpcNicknameTooLong          = fail.CreateGrpcClient(fail.TypeInvalidBody, "nickname must contain maximum 64 symbols")
	GrpcNicknameStartLetter      = fail.CreateGrpcClient(fail.TypeInvalidBody, "nickname must starts with latin letter")
	GrpcNicknameEndLetter        = fail.CreateGrpcClient(fail.TypeInvalidBody, "nickname must ends with latin letter or number")
	GrpcNicknameForbiddenSymbols = fail.CreateGrpcClient(fail.TypeInvalidBody, "nickname must contain only latin letters, numbers and '_'")
	GrpcNicknameForbiddenWord    = fail.CreateGrpcClient(fail.TypeInvalidBody, "nickname contains forbidden word")
	GrpcNicknameDoubleUnderscore = fail.CreateGrpcClient(fail.TypeInvalidBody, "nickname must contain no more than 1 underscore in a row")
	GrpcNicknameOccupied         = fail.CreateGrpcClient(typeNicknameOccupied, "this nickname already occupied")
)
