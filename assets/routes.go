package assets

const (
	RootDirPath = "./assets"

	MailTemplatesDirPath              = RootDirPath + "/mail"
	ProfileActivationMailTmplFilePath = MailTemplatesDirPath + "/profile_activation.html"
	NewLoginFilePath                  = MailTemplatesDirPath + "/new_login.html"
	PasswordResetMailTmplFilePath     = MailTemplatesDirPath + "/password_reset.html"
	PasswordChangedMailTmplFilePath   = MailTemplatesDirPath + "/password_changed.html"
	NicknameChangedMailTmplFilePath   = MailTemplatesDirPath + "/nickname_changed.html"
	ProfileDeletedMailTmplFilePath    = MailTemplatesDirPath + "/profile_deleted.html"

	NicknamesDirPath           = RootDirPath + "/nicknames"
	ForbiddenNicknamesFilePath = NicknamesDirPath + "/forbidden_nicknames.txt"
)
