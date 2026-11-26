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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// TestOIDCRejectsInvalidTimeBounds signs each invalid-time variant with the
// trusted fixture key. No malformed claim can become usable authentication
// evidence through otherwise valid signature, issuer, audience and nonce checks.
func TestOIDCRejectsInvalidTimeBounds(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(OidcJWKSet{Keys: []OidcJWK{buildRSAJWK("time-key", &key.PublicKey)}})
	}))
	defer server.Close()
	now := time.Now().UTC().Truncate(time.Second)
	cases := []struct {
		name   string                   // rejected claim case label
		change func(*OidcIDTokenClaims) // mutation applied before signing
	}{
		{"missing expiry", func(c *OidcIDTokenClaims) { c.ExpiresAt = nil }},
		{"missing issuance", func(c *OidcIDTokenClaims) { c.IssuedAt = nil }},
		{"future issuance", func(c *OidcIDTokenClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(3 * time.Minute)) }},
		{"expired", func(c *OidcIDTokenClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(-10 * time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(-3 * time.Minute))
		}},
		{"reversed inside leeway", func(c *OidcIDTokenClaims) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(30 * time.Second))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := OidcIDTokenClaims{Nonce: "nonce", RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://issuer.example", Subject: "subject", Audience: jwt.ClaimStrings{"client"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute))}}
			tc.change(&claims)
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "time-key"
			signed, err := token.SignedString(key)
			require.NoError(t, err)
			got, err := (OIDCClient{}).ValidateIDToken(context.Background(), OIDCOptions{IssuerURL: claims.Issuer, ClientID: "client", JWKSURL: server.URL, AllowedSigningAlgs: "RS256", ClockSkewSeconds: 120}, signed, "nonce")
			require.Error(t, err)
			require.Nil(t, got)
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
