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
// transport. Its configured endpoints are validated during composition; the
// client retains system TLS verification, finite timeouts and a strict response
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

// NewCentralOIDCClient constructs a reusable bounded transport for the central
// provider. System certificate checks remain enabled, and redirects return to
// the caller instead of carrying credentials to a different destination.
func NewCentralOIDCClient() *CentralOIDCClient {
	return &CentralOIDCClient{http: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// ExchangeCode redeems the single-use code with its S256 verifier and exact
// configured callback. The confidential central client has no public-client
// fallback, and any returned refresh credential is discarded by this finite
// session profile.
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
	// OAuth token_type is case-insensitive. Accept its valid letter cases while
	// retaining the exact credentials and rejecting every other token scheme.
	if json.Unmarshal(data, &token) != nil ||
		!strings.EqualFold(token.TokenType, "Bearer") ||
		token.AccessToken == "" || token.IDToken == "" {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	// This first profile has no upstream refresh lifecycle. Discard the optional
	// refresh credential immediately instead of retaining unused long-lived authority.
	token.RefreshToken = ""
	return &token, nil
}

// FetchUserInfo retrieves the access credential's literal subject and optional
// profile through bounded transport. It requires a nonempty JSON string named
// sub and preserves that value exactly, including whitespace, for the core's
// comparison with the signed ID token before any profile data is used.
//
// Suggested profile fields retain the legacy parser's configured mappings.
// Its subject fallbacks and trimming do not apply to central authentication:
// a generic identifier or normalized value cannot substitute for the UserInfo
// subject that the provider actually returned.
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
	var userInfo map[string]json.RawMessage
	if json.Unmarshal(data, &userInfo) != nil {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	var subject string
	if json.Unmarshal(userInfo["sub"], &subject) != nil || subject == "" {
		return nil, identity.ErrCentralEvidenceInvalid
	}
	claims := OidcParseUserInfo(string(data), options)
	// The legacy parser accepts alternate ID paths and trims identifiers. Keep
	// the literal sub so Finish compares the provider's unchanged subject.
	claims.Subject = subject
	return claims, nil
}

// ValidateIDToken loads bounded trusted keys and invokes the shared signature,
// issuer, audience and time verifier. Central authentication also requires the
// original nonce and a matching authorized party before retaining verified
// claims.
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

// read consumes one bounded successful JSON response and discards sensitive
// diagnostics. Cancellation and provider outages remain unavailable, while
// redirects and protocol rejection fail authentication without forwarding
// credentials to a different endpoint.
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
