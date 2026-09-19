package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mephistolie/chefbook-backend-auth/pkg/oauth/flow"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	AuthenticatedAt int64
	VerifiedEmail   bool   `json:"verified_email"`
	UserId          string `json:"id" binding:"required"`
	Email           string `json:"email" binding:"required"`
}

type OAuthProvider struct {
	StateStore flow.Store
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

func (p *OAuthProvider) CreateOAuthLink(ctx context.Context, redirectUrl string) (string, error) {
	config := p.baseConfig
	config.RedirectURL = redirectUrl
	state, err := p.StateStore.CreateOAuthState(ctx, "google", redirectUrl, flow.Binding(ctx))
	if err != nil {
		return "", err
	}
	return config.AuthCodeURL(state), nil
}

func (p *OAuthProvider) GetAccessToken(ctx context.Context, code, state string, redirectUrl string) (string, error) {
	config := p.baseConfig
	config.RedirectURL = redirectUrl
	if err := p.StateStore.ConsumeOAuthState(ctx, "google", state, redirectUrl, flow.Binding(ctx)); err != nil {
		return "", err
	}
	tokens, err := config.Exchange(ctx, code)
	if err != nil {
		var oauthErr *oauth2.RetrieveError
		if errors.As(err, &oauthErr) && oauthErr.Response != nil && oauthErr.Response.StatusCode < 500 && oauthErr.Response.StatusCode != 429 {
			return "", err
		}
		return "", status.Error(codes.Unavailable, "google unavailable")
	}
	return tokens.AccessToken, nil
}

func (p *OAuthProvider) GetUserInfoByAccessToken(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	bearer := fmt.Sprintf("Bearer %s", accessToken)
	req, err := http.NewRequestWithContext(ctx, "GET", userInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", bearer)
	return p.getUserInfoByRequest(req)
}

func (p *OAuthProvider) GetUserInfoByIdToken(ctx context.Context, token string) (*UserInfoResponse, error) {
	if token == "" {
		return nil, errors.New("empty Google ID token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenInfoEndpoint+"?"+url.Values{"id_token": {token}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	res, err := p.client.Do(req)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "google unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode >= 500 || res.StatusCode == 429 {
		return nil, status.Error(codes.Unavailable, "google unavailable")
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("invalid Google ID token")
	}
	var claims struct {
		AuthTime      json.Number `json:"auth_time"`
		Sub           string      `json:"sub"`
		Audience      string      `json:"aud"`
		Issuer        string      `json:"iss"`
		Expiration    string      `json:"exp"`
		Email         string      `json:"email"`
		EmailVerified string      `json:"email_verified"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&claims); err != nil {
		return nil, err
	}
	expiration, err := strconv.ParseInt(claims.Expiration, 10, 64)
	if err != nil || expiration <= time.Now().Unix() || claims.Sub == "" || p.baseConfig.ClientID == "" || claims.Audience != p.baseConfig.ClientID || (claims.Issuer != "accounts.google.com" && claims.Issuer != "https://accounts.google.com") || claims.EmailVerified != "true" {
		return nil, errors.New("invalid Google ID token claims")
	}
	authTime, _ := claims.AuthTime.Int64()
	return &UserInfoResponse{UserId: claims.Sub, Email: claims.Email, VerifiedEmail: true, AuthenticatedAt: authTime}, nil
}

func (p *OAuthProvider) getUserInfoByRequest(req *http.Request) (*UserInfoResponse, error) {
	res, err := p.client.Do(req)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "google unavailable")
	}
	if res.StatusCode >= 500 || res.StatusCode == 429 {
		res.Body.Close()
		return nil, status.Error(codes.Unavailable, "google unavailable")
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, errors.New("invalid google response")
	}

	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return nil, err
	}
	var resBody UserInfoResponse
	if err := json.Unmarshal(bodyBytes, &resBody); err != nil {
		return nil, err
	}
	if resBody.UserId == "" || !resBody.VerifiedEmail {
		return nil, errors.New("invalid Google identity")
	}
	return &resBody, nil
}

func (p *OAuthProvider) GetUserInfoByCode(ctx context.Context, code, state, redirectUrl string) (*UserInfoResponse, error) {
	accessToken, err := p.GetAccessToken(ctx, code, state, redirectUrl)
	if err != nil {
		return nil, err
	}

	info, err := p.GetUserInfoByAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	return info, nil
}
