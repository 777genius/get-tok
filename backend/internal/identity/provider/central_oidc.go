package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// central_oidc.go supplies the central browser flow with bounded credential
// transport. Its configured endpoints are validated during composition; every
// request uses ordinary verified TLS, a finite timeout and a strict response
// bound. Redirects are returned as failures so neither authorization codes nor
// client credentials can be forwarded to an unexpected destination.
//
// Signature, issuer, audience, nonce and timestamp checks reuse the existing
// provider verifier. This adapter changes network custody and error handling,
// without introducing an alternate token-validation policy. Provider response
// bodies and detailed credential errors do not escape into product logs or
// browser responses. Userinfo remains bound to the verified ID-token subject
// by the core flow after this adapter returns its observations.

// CentralOIDCClient owns the no-redirect transport for the configured central provider.
type CentralOIDCClient struct {
	http *http.Client // TLS-verified, bounded credential requests
}

// NewCentralOIDCClient constructs transport without weakening system certificate checks.
func NewCentralOIDCClient() *CentralOIDCClient {
	return &CentralOIDCClient{http: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// ExchangeCode redeems the single-use code with mandatory S256 verifier and exact callback.
// Central configuration uses one confidential client and never accepts a public-client fallback.
func (c *CentralOIDCClient) ExchangeCode(ctx context.Context, options OIDCOptions, code, redirect, verifier string) (*identity.OIDCTokenResponse, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {options.ClientID}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, options.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	request.SetBasicAuth(url.QueryEscape(options.ClientID), url.QueryEscape(options.ClientSecret))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	data, err := c.read(request)
	if err != nil {
		return nil, err
	}
	var token identity.OIDCTokenResponse
	if json.Unmarshal(data, &token) != nil || token.TokenType != "Bearer" && token.TokenType != "bearer" || token.AccessToken == "" || token.IDToken == "" {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	// This first profile has no upstream refresh lifecycle. Discard the optional
	// refresh credential immediately instead of retaining unused long-lived authority.
	token.RefreshToken = ""
	return &token, nil
}

// FetchUserInfo retrieves the access credential's subject and optional verified profile.
func (c *CentralOIDCClient) FetchUserInfo(ctx context.Context, options OIDCOptions, token *identity.OIDCTokenResponse) (*identity.OIDCUserInfoClaims, error) {
	if token == nil || token.AccessToken == "" || strings.ContainsAny(token.AccessToken, " \t\r\n") {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, options.UserInfoURL, nil)
	if err != nil {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	data, err := c.read(request)
	if err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	return OidcParseUserInfo(string(data), options), nil
}

// ValidateIDToken loads bounded trusted keys and applies the shared signed-token verifier.
func (c *CentralOIDCClient) ValidateIDToken(ctx context.Context, options OIDCOptions, token, nonce string) (*identity.OIDCVerifiedClaims, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, options.JWKSURL, nil)
	if err != nil {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	data, err := c.read(request)
	if err != nil {
		return nil, err
	}
	var keys OidcJWKSet
	if json.Unmarshal(data, &keys) != nil || len(keys.Keys) == 0 || len(keys.Keys) > 32 {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	claims, err := oidcValidateIDTokenWithKeys(options, token, nonce, &keys)
	if err != nil || claims.Nonce != nonce || claims.Azp != "" && claims.Azp != options.ClientID {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	return oidcVerifiedClaims(claims), nil
}

// read consumes one small successful JSON response and discards sensitive diagnostics.
// Cancellation and provider outages remain unavailable; protocol rejection is not retryable login state.
func (c *CentralOIDCClient) read(request *http.Request) ([]byte, error) {
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, identity.ErrCentralUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 || response.StatusCode >= 500 {
		return nil, identity.ErrCentralUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	return data, nil
}
