package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// oidc_oauth_test.go exercises signed provider authentication observations and
// mandatory token-time bounds using an HTTP-served local JWKS fixture. The
// signing key belongs only to each test, so successful validation still passes
// through the production signature, issuer, audience and nonce checks. Tests
// distinguish authentication time from issuance time instead of treating a
// renewed token as evidence of a new upstream authentication ceremony.
//
// Rejected cases retain otherwise valid signatures and provider configuration.
// They isolate missing or contradictory time claims, future issuance and
// expired credentials, including times inside the configured leeway. Userinfo
// parsing has its own profile-focused case because profile hints do not confer
// the stronger assurance required by a central consumer policy.

// TestOIDCParseAndValidateIDToken signs a multiple-audience token with matching
// authorized party and nonce, and serves its public key locally. Validation retains
// issuer and subject; supplying a different expected nonce rejects that signed token.
func TestOIDCParseAndValidateIDToken(t *testing.T) {
	// Use one fixture RSA key for the accepted and nonce-rejected requests so
	// the changed expectation is evaluated against otherwise identical signed token data.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "kid-1"
	jwks := OidcJWKSet{Keys: []OidcJWK{buildRSAJWK(kid, &priv.PublicKey)}}
	// The HTTP handler runs in another goroutine. Publish its request count
	// atomically before the completed client call checks how often JWKS was fetched.
	var jwksRequests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksRequests.Add(1)
		require.NoError(t, json.NewEncoder(w).Encode(jwks))
	}))
	defer srv.Close()

	now := time.Now()
	claims := OidcIDTokenClaims{
		Nonce:                 "nonce-ok",
		Azp:                   "client-1",
		AuthTime:              jwt.NewNumericDate(now.Add(-time.Hour)),
		SessionID:             "provider-session-1",
		AuthenticationContext: "observed-context",
		AuthenticationMethods: []string{"pwd"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "subject-1",
			Audience:  jwt.ClaimStrings{"client-1", "another-aud"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)

	cfg := OIDCOptions{
		ClientID:           "client-1",
		IssuerURL:          "https://issuer.example.com",
		JWKSURL:            srv.URL,
		AllowedSigningAlgs: "RS256",
		ClockSkewSeconds:   120,
	}

	parsed, err := OidcParseAndValidateIDToken(context.Background(), cfg, signed, "nonce-ok")
	require.NoError(t, err)
	require.Equal(t, int64(1), jwksRequests.Load(), "valid verification must fetch its JWKS exactly once")
	require.Equal(t, "subject-1", parsed.Subject)
	require.Equal(t, "https://issuer.example.com", parsed.Issuer)
	verified, err := (OIDCClient{}).ValidateIDToken(context.Background(), cfg, signed, "nonce-ok")
	require.NoError(t, err)
	require.Equal(t, claims.IssuedAt.UTC(), verified.IssuedAt)
	require.Equal(t, claims.ExpiresAt.UTC(), verified.ExpiresAt)
	require.NotNil(t, verified.AuthenticatedAt)
	require.Equal(t, claims.AuthTime.UTC(), *verified.AuthenticatedAt)
	require.Equal(t, claims.SessionID, verified.SessionID)
	require.Equal(t, claims.AuthenticationContext, verified.AuthenticationContext)
	require.Equal(t, claims.AuthenticationMethods, verified.AuthenticationMethods)
	claims.AuthTime = nil
	withoutAuth := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	withoutAuth.Header["kid"] = kid
	withoutAuthText, err := withoutAuth.SignedString(priv)
	require.NoError(t, err)
	verified, err = (OIDCClient{}).ValidateIDToken(context.Background(), cfg, withoutAuthText, "nonce-ok")
	require.NoError(t, err)
	require.Nil(t, verified.AuthenticatedAt)

	_, err = OidcParseAndValidateIDToken(context.Background(), cfg, signed, "bad-nonce")
	require.Error(t, err)
}

// TestOIDCRejectsInvalidTimeBounds signs a valid single-audience control and
// each invalid-time variant with the same trusted key. Specific time errors
// distinguish the intended rejection from a signature, audience or nonce failure.
func TestOIDCRejectsInvalidTimeBounds(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(OidcJWKSet{Keys: []OidcJWK{buildRSAJWK("time-key", &key.PublicKey)}}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	// Match the whole-second precision used by JWT NumericDate claims.
	now := time.Now().UTC().Truncate(time.Second)
	cases := []struct {
		name     string                   // token-time case label
		change   func(*OidcIDTokenClaims) // optional mutation before signing
		wantErr  error                    // expected JWT validation sentinel
		wantText string                   // exact verifier error, empty on success
	}{
		{"valid single audience", nil, nil, ""},
		{"missing expiry", func(c *OidcIDTokenClaims) { c.ExpiresAt = nil }, jwt.ErrTokenRequiredClaimMissing, ""},
		{"missing issuance", func(c *OidcIDTokenClaims) { c.IssuedAt = nil }, nil, "id_token invalid time bounds"},
		{"future issuance", func(c *OidcIDTokenClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(3 * time.Minute)) }, jwt.ErrTokenUsedBeforeIssued, ""},
		{"expired", func(c *OidcIDTokenClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(-10 * time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(-3 * time.Minute))
		}, jwt.ErrTokenExpired, ""},
		{"reversed inside leeway", func(c *OidcIDTokenClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(30 * time.Second))
		}, nil, "id_token invalid time bounds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := OidcIDTokenClaims{Nonce: "nonce", RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://issuer.example", Subject: "subject", Audience: jwt.ClaimStrings{"client"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute))}}
			if tc.change != nil {
				tc.change(&claims)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "time-key"
			signed, err := token.SignedString(key)
			require.NoError(t, err)
			got, err := (OIDCClient{}).ValidateIDToken(context.Background(), OIDCOptions{IssuerURL: claims.Issuer, ClientID: "client", JWKSURL: server.URL, AllowedSigningAlgs: "RS256", ClockSkewSeconds: 120}, signed, "nonce")
			if tc.wantErr == nil && tc.wantText == "" {
				require.NoError(t, err)
				require.Equal(t, claims.Subject, got.Subject)
				return
			}
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.EqualError(t, err, tc.wantText)
			}
			require.Nil(t, got)
		})
	}
}

// TestOIDCValidationPreflight rejects local token and algorithm errors before
// contacting an unavailable provider. The request counter protects first-error
// ordering and prevents network timeout from hiding invalid local configuration.
func TestOIDCValidationPreflight(t *testing.T) {
	// The server handler can run independently of test assertions. Atomic
	// accounting exposes any forbidden request without introducing a test data race.
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	for _, row := range []struct {
		name       string // local preflight case name
		token      string // token text before normalization
		algorithms string // configured signing-method list
		want       string // expected first local error
	}{
		{"missing token", " ", "RS256", "missing id_token"},
		{"empty algorithms", "fixture-token", ", ,", "empty allowed signing algorithms"},
		{"token error precedes algorithms", " ", ", ,", "missing id_token"},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := OidcParseAndValidateIDToken(t.Context(), OIDCOptions{JWKSURL: server.URL, AllowedSigningAlgs: row.algorithms}, row.token, "")
			require.EqualError(t, err, row.want)
			require.Zero(t, requests.Load())
		})
	}
}

// TestOIDCParseUserInfoIncludesSuggestedProfile supplies standard userinfo
// identity, display, avatar, and verification fields. Assertions check subject,
// username, display name, and avatar, plus a present, true email-verification flag.
func TestOIDCParseUserInfoIncludesSuggestedProfile(t *testing.T) {
	cfg := OIDCOptions{}

	claims := OidcParseUserInfo(`{
		"sub":"subject-1",
		"preferred_username":"alice",
		"name":"Alice Example",
		"picture":"https://cdn.example/avatar.png",
		"email":"alice@example.com",
		"email_verified":true
	}`, cfg)

	require.Equal(t, "subject-1", claims.Subject)
	require.Equal(t, "alice", claims.Username)
	require.Equal(t, "Alice Example", claims.DisplayName)
	require.Equal(t, "https://cdn.example/avatar.png", claims.AvatarURL)
	require.NotNil(t, claims.EmailVerified)
	require.True(t, *claims.EmailVerified)
}

// buildRSAJWK encodes the supplied nonnil RSA public key as an RS256 signing
// candidate with kid metadata. Modulus and exponent become unsigned big-endian
// base64url fields used by the local JWKS response.
func buildRSAJWK(kid string, pub *rsa.PublicKey) OidcJWK {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return OidcJWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}
}
