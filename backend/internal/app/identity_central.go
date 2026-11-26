package app

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/config"
	"github.com/TokenFlux/TokenRouter/internal/identity"
	identityhttp "github.com/TokenFlux/TokenRouter/internal/identity/httpapi"
	identitypostgres "github.com/TokenFlux/TokenRouter/internal/identity/postgres"
	identityprovider "github.com/TokenFlux/TokenRouter/internal/identity/provider"
)

// identity_central.go composes the optional central browser flow from existing
// account services and dedicated authority, OIDC and persistence adapters. The
// mutable legacy OIDC provider configuration cannot change this authority's
// issuer, consumer, credentials or continuity identifier after startup. The
// central binding uses the same PostgreSQL and Ent participants as local users,
// preserving local identifiers and atomic signup or migration ownership.
//
// This first qualified TEST profile admits ordinary provider-session control.
// Organizational actions retain a separate required profile that composition
// deliberately leaves unavailable. Route families with wholly organizational
// meaning are classified here, while mixed key and usage handlers must evaluate
// their actual selected resource or restrict queries to personal projections.
// Existing product role checks and machine credential policies remain separate.

// provideCentralIdentity assembles one startup-pinned BFF or a disabled capability handler.
// Independent-continuity policy fields remain empty until a native provider profile qualifies.
func provideCentralIdentity(cfg *config.Config, db *sql.DB, graph *identityAuthGraph, users *identity.UserService, settings *identityAuthSettings, totp *identity.TotpService, cipher identity.SecretEncryptor) *identityhttp.CentralHandler {
	c := cfg.CentralIdentity
	handler := &identityhttp.CentralHandler{Options: identityhttp.CentralHTTPOptions{Origin: c.Origin, ProviderName: c.ProviderName, TestLoopback: c.TestLoopback, Access: centralRouteAccess}, Auth: graph.Core, Users: users, BindingSettings: settings}
	if !c.Enabled {
		return handler
	}
	providerBase := c.IssuerURL + "/protocol/openid-connect/"
	policy := identity.CentralConsumerPolicy{ConsumerID: c.ConsumerID, AuthorityIncarnation: c.AuthorityIncarnation, OrdinaryPolicyID: "gettok-ordinary-login", OrdinaryPolicyVersion: 1}
	options := identity.CentralLoginOptions{
		Policy: policy, Providers: append([]string(nil), c.Providers...), TestBindingProfile: c.TestBindingProfile,
		OIDC: identity.OIDCOAuthOptions{Enabled: true, ProviderName: c.ProviderName, ClientID: c.ClientID, ClientSecret: c.ClientSecret, IssuerURL: c.IssuerURL, AuthorizeURL: providerBase + "auth", TokenURL: providerBase + "token", UserInfoURL: providerBase + "userinfo", JWKSURL: providerBase + "certs", RedirectURL: c.Origin + "/api/v1/auth/central/callback", Scopes: "openid email profile", AllowedSigningAlgs: "RS256", ClockSkewSeconds: 5, UsePKCE: true, ValidateIDToken: true, TokenAuthMethod: "client_secret_basic"},
	}
	handler.Flow = &identity.CentralFlow{Options: options, Store: identitypostgres.NewCentralSessionStore(db, graph.Client, graph.State, time.Now), Authority: identityprovider.NewCentralIdentityClient(identityprovider.CentralAuthorityOptions{BaseURL: c.APIURL, TokenURL: providerBase + "token", WorkloadClientID: c.WorkloadClientID, WorkloadClientSecret: c.WorkloadClientSecret}), Provider: identityprovider.NewCentralOIDCClient(), Cipher: cipher, Auth: graph.Core, TOTP: totp, SignupDefaults: settings.GetAuthSourceDefaultSettings, Now: time.Now}
	return handler
}

// centralRouteAccess identifies wholly protected resource families without granting roles.
// Mixed personal/team resources perform their additional resolved-resource checks downstream.
func centralRouteAccess(_ context.Context, _ int64, route, method string) (identity.CentralAccessClass, error) {
	if route == "/api/v1/team" || strings.HasPrefix(route, "/api/v1/team/") {
		if method == http.MethodGet || method == http.MethodHead {
			return identity.CentralAccessOrganizational, nil
		}
		return identity.CentralAccessSensitive, nil
	}
	if strings.HasPrefix(route, "/api/v1/admin/") || route == "/api/v1/auth/oauth/bind-token" || route == "/api/v1/user/password" || strings.HasPrefix(route, "/api/v1/user/account-bindings/") || strings.HasPrefix(route, "/api/v1/user/auth-identities/") || strings.HasPrefix(route, "/api/v1/user/totp/") || strings.HasPrefix(route, "/api/v1/user/passkeys") {
		return identity.CentralAccessSensitive, nil
	}
	return identity.CentralAccessOrdinary, nil
}
