package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
	"time"
)

const (
	userInfoEndpoint  = "https://www.googleapis.com/oauth2/v2/userinfo"
	tokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo"
)

type OAuthParams struct {
	Display      string
	ResponseType string
}

type UserInfoResponse struct {
	UserId string `json:"id" binding:"required"`
	Email  string `json:"email" binding:"required"`
}

type OAuthProvider struct {
	client     http.Client
	baseConfig oauth2.Config
	state      string
}

func NewOAuthProvider(clientId, clientSecret, state string, scopes []string) *OAuthProvider {
	return &OAuthProvider{
		client: http.Client{Timeout: 10 * time.Second},
		baseConfig: oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		},
		state: state,
	}
}

func (p *OAuthProvider) CreateOAuthLink(redirectUrl string) string {
	config := p.baseConfig
	config.RedirectURL = redirectUrl
	return config.AuthCodeURL(p.state)
}

func (p *OAuthProvider) GetAccessToken(code, state string, redirectUrl string) (string, error) {
	config := p.baseConfig
	config.RedirectURL = redirectUrl
	if p.state != state {
		return "", errors.New("invalid state")
	}
	tokens, err := config.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}
	return tokens.AccessToken, nil
}

func (p *OAuthProvider) GetUserInfoByAccessToken(accessToken string) (*UserInfoResponse, error) {
	bearer := fmt.Sprintf("Bearer %s", accessToken)
	req, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", bearer)
	return p.getUserInfoByRequest(req)
}

func (p *OAuthProvider) GetUserInfoByIdToken(idToken string) (*UserInfoResponse, error) {
	url := fmt.Sprintf("%s?id_token=%s", tokenInfoEndpoint, idToken)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return p.getUserInfoByRequest(req)
}

func (p *OAuthProvider) getUserInfoByRequest(req *http.Request) (*UserInfoResponse, error) {
	res, err := p.client.Do(req)
	if err != nil || res.StatusCode != 200 {
		return nil, errors.New("error google response")
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var resBody UserInfoResponse
	if err := json.Unmarshal(bodyBytes, &resBody); err != nil {
		return nil, err
	}
	return &resBody, nil
}

func (p *OAuthProvider) GetUserInfoByCode(code, state, redirectUrl string) (*UserInfoResponse, error) {
	accessToken, err := p.GetAccessToken(code, state, redirectUrl)
	if err != nil {
		return nil, err
	}

	info, err := p.GetUserInfoByAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	return info, nil
}
