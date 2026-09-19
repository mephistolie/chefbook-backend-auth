package assets

const (
	RootDirPath = "./assets"

	EmailBindingMailTmplFilePath           = RootDirPath + "/mail/email_binding.html"
	MailTemplatesDirPath                   = RootDirPath + "/mail"
	ProfileActivationMailTmplFilePath      = MailTemplatesDirPath + "/profile_activation.html"
	NewLoginFilePath                       = MailTemplatesDirPath + "/new_login.html"
	PasswordResetMailTmplFilePath          = MailTemplatesDirPath + "/password_reset.html"
	PasswordChangedMailTmplFilePath        = MailTemplatesDirPath + "/password_changed.html"
	UsernameChangedMailTmplFilePath        = MailTemplatesDirPath + "/username_changed.html"
	ProfileDeletionRequestMailTmplFilePath = MailTemplatesDirPath + "/profile_deletion_request.html"
	ProfileDeletedMailTmplFilePath         = MailTemplatesDirPath + "/profile_deleted.html"

	UsernamesDirPath           = RootDirPath + "/usernames"
	ForbiddenUsernamesFilePath = UsernamesDirPath + "/forbidden_usernames.txt"
)
