package vk

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	authorizeUrl      = "https://oauth.vk.com/authorize"
	accessTokenUrl    = "https://oauth.vk.com/access_token"
	clientIdParam     = "client_id"
	redirectUriParam  = "redirect_uri"
	displayParam      = "display"
	displayPage       = "page"
	displayPopup      = "popup"
	displayMobile     = "mobile"
	scopeParam        = "scope"
	responseTypeParam = "response_type"
	responseTypeToken = "token"
	responseTypeCode  = "code"
	stateParam        = "state"
	clientSecretParam = "client_secret"
	codeParam         = "code"
)

var (
	acceptableDisplays      = []string{displayPage, displayPopup, displayMobile}
	acceptableResponseTypes = []string{responseTypeToken, responseTypeCode}
)

type OAuthParams struct {
	Display      string
	ResponseType string
	RedirectUri  string
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token" binding:"required"`
	ExpiresIn   int64  `json:"expires_in,omitempty" binding:"required"`
	UserId      int64  `json:"user_id" binding:"required"`
	Email       string `json:"email"`
}

type OAuthProvider struct {
	client       http.Client
	clientId     string
	clientSecret string
	scope        string
	state        string
}

func NewOAuthProvider(clientId, clientSecret, scope, state string) *OAuthProvider {
	return &OAuthProvider{
		client:       http.Client{Timeout: 10 * time.Second},
		clientId:     clientId,
		clientSecret: clientSecret,
		scope:        scope,
		state:        state,
	}
}

func (p *OAuthProvider) CreateOAuthLink(params OAuthParams) (string, error) {
	var display = displayPage
	if contains(acceptableDisplays, params.Display) {
		display = params.Display
	}
	var responseType = responseTypeCode
	if contains(acceptableResponseTypes, params.ResponseType) {
		responseType = params.ResponseType
	}

	baseUrl, err := url.Parse(authorizeUrl)
	if err != nil {
		return "", err
	}
	urlParams := url.Values{}
	urlParams.Add(clientIdParam, p.clientId)
	urlParams.Add(redirectUriParam, params.RedirectUri)
	urlParams.Add(displayParam, display)
	urlParams.Add(scopeParam, p.scope)
	urlParams.Add(responseTypeParam, responseType)
	urlParams.Add(stateParam, p.state)
	baseUrl.RawQuery = urlParams.Encode()
	return baseUrl.String(), nil
}

func (p *OAuthProvider) GetAccessToken(code, state string, redirectUri string) (*AccessTokenResponse, error) {
	if p.state != state {
		return nil, errors.New("invalid state")
	}

	requestUrl, err := p.createGetAccessTokenUrl(code, redirectUri)
	if err != nil {
		return nil, err
	}

	res, err := p.client.Get(requestUrl)
	if err != nil || res.StatusCode != 200 {
		return nil, errors.New("error vk response")
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var resBody AccessTokenResponse
	if err := json.Unmarshal(bodyBytes, &resBody); err != nil {
		return nil, err
	}
	return &resBody, nil
}

func (p *OAuthProvider) createGetAccessTokenUrl(code string, redirectUri string) (string, error) {
	baseUrl, err := url.Parse(accessTokenUrl)
	if err != nil {
		return "", err
	}
	urlParams := url.Values{}
	urlParams.Add(clientIdParam, p.clientId)
	urlParams.Add(clientSecretParam, p.clientSecret)
	urlParams.Add(redirectUriParam, redirectUri)
	urlParams.Add(codeParam, code)
	baseUrl.RawQuery = urlParams.Encode()

	return baseUrl.String(), nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
