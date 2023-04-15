package oauth

import "github.com/mephistolie/chefbook-backend-auth/pkg/oauth/google"
import "github.com/mephistolie/chefbook-backend-auth/pkg/oauth/vk"

type Providers struct {
	Google google.OAuthProvider
	Vk     vk.OAuthProvider
}
