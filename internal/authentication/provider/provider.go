// Package provider contains network adapters; errors never include tokens/URLs.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"google.golang.org/api/googleapi"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	engine "github.com/mephistolie/chefbook-backend-auth/internal/authentication"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

type Google struct{ ClientID, ClientSecret string }

func (g Google) config(redirect string) oauth2.Config {
	return oauth2.Config{ClientID: g.ClientID, ClientSecret: g.ClientSecret, RedirectURL: redirect, Endpoint: google.Endpoint, Scopes: []string{"openid", "email", "profile"}}
}
func (g Google) Authorize(state, nonce, challenge, redirect string, reauth bool) (string, error) {
	if g.ClientID == "" {
		return "", engine.ErrUnavailable
	}
	c := g.config(redirect)
	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("code_challenge", challenge), oauth2.SetAuthURLParam("code_challenge_method", "S256")}
	if reauth {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", "0"), oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	return c.AuthCodeURL(state, opts...), nil
}
func (g Google) Exchange(ctx context.Context, code, redirect, verifier string) (engine.ProviderIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := g.config(redirect)
	tokens, err := c.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return engine.ProviderIdentity{}, providerError(err)
	}
	raw, _ := tokens.Extra("id_token").(string)
	return g.Native(ctx, raw)
}
func (g Google) Native(ctx context.Context, raw string) (engine.ProviderIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if g.ClientID == "" || raw == "" {
		return engine.ProviderIdentity{}, engine.ErrCredentials
	}
	p, err := idtoken.Validate(ctx, raw, g.ClientID)
	if err != nil {
		return engine.ProviderIdentity{}, providerError(err)
	}
	if p.Issuer != "accounts.google.com" && p.Issuer != "https://accounts.google.com" || p.Subject == "" || p.Expires <= time.Now().Unix() {
		return engine.ProviderIdentity{}, engine.ErrCredentials
	}
	email, _ := p.Claims["email"].(string)
	verified, _ := p.Claims["email_verified"].(bool)
	if !verified {
		email = ""
	}
	nonce, _ := p.Claims["nonce"].(string)
	v := engine.ProviderIdentity{Subject: p.Subject, Email: email, Nonce: nonce}
	if t, ok := p.Claims["auth_time"].(float64); ok {
		v.AuthenticatedAt = time.Unix(int64(t), 0)
	}
	return v, nil
}

// VK legacy authorization-code adapter preserves deployed VK app compatibility.
// VK does not assert auth_time here: it cannot satisfy fresh reauthentication.
type VK struct{ ClientID, ClientSecret string }

func (v VK) Authorize(state, nonce, challenge, redirect string, reauth bool) (string, error) {
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", engine.ErrInvalid
	}
	if v.ClientID == "" {
		return "", engine.ErrUnavailable
	}
	q := url.Values{"client_id": {v.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"email"}, "state": {state}}
	return "https://oauth.vk.com/authorize?" + q.Encode(), nil
}
func (v VK) Native(context.Context, string) (engine.ProviderIdentity, error) {
	return engine.ProviderIdentity{}, engine.ErrUnavailable
}
func (v VK) Exchange(ctx context.Context, code, redirect, verifier string) (engine.ProviderIdentity, error) {
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return engine.ProviderIdentity{}, engine.ErrInvalid
	}
	q := url.Values{"client_id": {v.ClientID}, "client_secret": {v.ClientSecret}, "redirect_uri": {redirect}, "code": {code}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth.vk.com/access_token", nil)
	if err != nil {
		return engine.ProviderIdentity{}, engine.ErrUnavailable
	}
	req.URL.RawQuery = q.Encode()
	client := http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return engine.ProviderIdentity{}, engine.ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode >= 500 || res.StatusCode == 429 {
		return engine.ProviderIdentity{}, engine.ErrUnavailable
	}
	if res.StatusCode != 200 {
		return engine.ProviderIdentity{}, engine.ErrCredentials
	}
	var data struct {
		UserID int64  `json:"user_id"`
		Email  string `json:"email"`
		Token  string `json:"access_token"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&data) != nil || data.UserID <= 0 || data.Token == "" {
		return engine.ProviderIdentity{}, engine.ErrCredentials
	}
	return engine.ProviderIdentity{Subject: strconv.FormatInt(data.UserID, 10), Email: data.Email}, nil
}

func providerError(err error) error {
	var n net.Error
	if errors.As(err, &n) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return engine.ErrUnavailable
	}
	var oauth *oauth2.RetrieveError
	if errors.As(err, &oauth) && oauth.Response != nil && (oauth.Response.StatusCode >= 500 || oauth.Response.StatusCode == 429) {
		return engine.ErrUnavailable
	}
	var api *googleapi.Error
	if errors.As(err, &api) && (api.Code >= 500 || api.Code == 429) {
		return engine.ErrUnavailable
	}
	return engine.ErrCredentials
}
