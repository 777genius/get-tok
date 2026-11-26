package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/identity/httpapi/authctx"
	"github.com/TokenFlux/TokenRouter/internal/server/clientip"
	response "github.com/TokenFlux/TokenRouter/internal/server/httpx"
)

// central_auth.go keeps central credentials behind an opaque browser session.
// Authorization codes, provider tokens, account proofs and workload credentials
// never enter response JSON or frontend URL fragments. The callback accepts a
// consumed browser-bound transaction and returns only a fixed frontend route;
// frontend session bootstrap exposes the existing local profile and a separate
// CSRF secret, both under no-store response policy.
//
// Cookie authentication is selected before legacy Bearer authentication, and
// mixed credentials are rejected. Protected reads and mutations require the
// session's CSRF secret, preventing another tab's cookie from silently changing
// the displayed owner. Mutations also require the configured exact origin;
// the dedicated session bootstrap permits the initial proof-free same-origin read.
// Logout persists local revocation and leaves an inert cookie to expire, so a
// delayed response cannot erase a newer login. It remains usable during an
// upstream outage. Only an explicit loopback TEST configuration uses
// non-Secure cookies, under names distinct from the production host cookies.

const (
	centralSessionCookie     = "__Host-gettok-central"       // production host-only browser credential
	centralLoginCookie       = "__Host-gettok-central-login" // production browser-transaction binding
	centralTestSessionCookie = "gettok-central-test"         // explicit loopback TEST browser credential
	centralTestLoginCookie   = "gettok-central-login-test"   // explicit loopback TEST transaction binding
	centralAuthenticatedKey  = "central_authenticated"       // private request admission snapshot
)

// CentralHTTPOptions carries browser custody and product assurance classification.
type CentralHTTPOptions struct {
	Origin       string                     // exact configured browser origin
	ProviderName string                     // display label independent of the broker alias
	TestLoopback bool                       // explicit local TEST cookie transport
	BackendMode  func(context.Context) bool // current panel restriction on new shared login
	// Access classifies product resources after current identity was resolved.
	// It performs no role grant; ordinary product authorization still runs afterward.
	Access func(context.Context, int64, string, string) (identity.CentralAccessClass, error)
}

// CentralHandler assembles central browser custody with existing local profile readers.
type CentralHandler struct {
	Flow            *identity.CentralFlow // nil means shared authentication is disabled
	Options         CentralHTTPOptions    // immutable browser and assurance settings
	Auth            *identity.AuthService // existing CAPTCHA and legacy credential verifier
	Users           *identity.UserService // current local account and profile reader
	BindingSettings BindingSettings       // existing legacy session-binding admission
}

// CentralStartRequest retains explicit intent and existing action-CAPTCHA proof.
type CentralStartRequest struct {
	Intent                   string `json:"intent"`                    // login, register or admitted TEST bind
	Provider                 string `json:"provider,omitempty"`        // allowlisted Keycloak broker alias
	InvitationCode           string `json:"invitation_code,omitempty"` // existing signup invitation
	Password                 string `json:"password,omitempty"`        // TEST prior-owner password proof
	TOTPCode                 string `json:"totp_code,omitempty"`       // TEST previously enrolled local factor proof
	OAuthStartCaptchaRequest        // existing anonymous action challenge fields
}

// RegisterCentralAuthenticationRoutes mounts the separately bounded shared flow.
// The surrounding application supplies the same fail-closed rate limiter as legacy login.
func RegisterCentralAuthenticationRoutes(v1 *gin.RouterGroup, handler *CentralHandler, guards AuthRouteMiddleware) {
	if handler == nil {
		return
	}
	group := v1.Group("/auth/central", guards.BackendAuth, guards.Audit)
	group.GET("/config", handler.Config)
	group.POST("/start", guards.Limit("central-auth-start", 20, time.Minute), handler.Start)
	group.GET("/callback", guards.Limit("central-auth-callback", 30, time.Minute), handler.Callback)
	group.GET("/session", guards.Limit("central-auth-session", 60, time.Minute), handler.Session)
	group.POST("/logout", handler.Logout)
}

// Config exposes only display and capability data, never endpoints or client credentials.
func (h *CentralHandler) Config(c *gin.Context) {
	centralNoStore(c)
	providers := make([]gin.H, 0)
	if h.Flow != nil {
		for _, alias := range h.Flow.Options.Providers {
			label := alias
			if alias == "github" {
				label = "GitHub"
			}
			if alias == "gitlab" {
				label = "GitLab"
			}
			providers = append(providers, gin.H{"id": alias, "label": label})
		}
	}
	loginEnabled := h.Flow != nil && (h.Options.BackendMode == nil || !h.Options.BackendMode(c.Request.Context()))
	response.Success(c, gin.H{"enabled": loginEnabled, "provider_name": h.Options.ProviderName, "providers": providers, "legacy_binding_enabled": loginEnabled && h.Flow.Options.TestBindingProfile == identity.CentralTestBindingProfile})
}

// Start validates exact origin, explicit intent and its existing admission gates.
// Only bind may carry a legacy Bearer, and that token alone cannot authorize migration.
func (h *CentralHandler) Start(c *gin.Context) {
	centralNoStore(c)
	if !h.enabled(c) || !h.browserOrigin(c, true) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16384)
	var input CentralStartRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		centralHTTPError(c, identity.ErrCentralEvidenceInvalid)
		return
	}
	var owner *identity.CentralOwnerProof
	if input.Intent == identity.CentralIntentBind {
		if h.HasCookie(c) || h.Flow.Options.TestBindingProfile != identity.CentralTestBindingProfile {
			centralHTTPError(c, identity.ErrCentralBindingDisabled)
			return
		}
		header := strings.Fields(c.GetHeader("Authorization"))
		if len(header) != 2 || !strings.EqualFold(header[0], "Bearer") {
			centralHTTPError(c, identity.ErrCentralProofRequired)
			return
		}
		_, user, ok := validateCurrentJWT(c, header[1], h.Auth, h.Users, h.BindingSettings, nil)
		if !ok {
			return
		}
		var err error
		owner, err = h.Flow.VerifyLegacyOwner(c.Request.Context(), user.ID, input.Password, input.TOTPCode)
		if err != nil {
			centralHTTPError(c, err)
			return
		}
	} else {
		if c.GetHeader("Authorization") != "" || input.Password != "" || input.TOTPCode != "" {
			centralHTTPError(c, identity.ErrCentralEvidenceInvalid)
			return
		}
		if err := h.Auth.VerifyActionCaptchaIfEnabled(c.Request.Context(), identity.CaptchaProof{TurnstileToken: input.TurnstileToken, TencentTicket: input.TencentCaptchaTicket, TencentRandstr: input.TencentCaptchaRandstr}, clientip.GetClientIP(c)); err != nil {
			response.ErrorFrom(c, err)
			return
		}
	}
	result, err := h.Flow.Begin(c.Request.Context(), input.Intent, input.Provider, input.InvitationCode, owner)
	if err != nil {
		centralHTTPError(c, err)
		return
	}
	h.cookie(c, true, result.BrowserSecret, result.ExpiresAt)
	response.Success(c, gin.H{"authorization_url": result.AuthorizationURL})
}

// Callback finishes the one-use transaction and replaces the opaque session only after commit.
// The browser sees a fixed callback route and a finite allowlist of error categories.
func (h *CentralHandler) Callback(c *gin.Context) {
	centralNoStore(c)
	if !h.enabled(c) {
		return
	}
	browser, err := h.readCookie(c, true)
	h.cookie(c, true, "", time.Time{})
	query := c.Request.URL.Query()
	if err != nil || c.Query("error") != "" || c.GetHeader("Authorization") != "" || len(query["state"]) != 1 || len(query["code"]) != 1 || len(query["iss"]) > 1 || c.Query("iss") != "" && c.Query("iss") != h.Flow.Options.OIDC.IssuerURL {
		h.callbackError(c, identity.ErrCentralSessionExpired)
		return
	}
	result, err := h.Flow.Finish(c.Request.Context(), c.Query("state"), browser, c.Query("code"))
	if err != nil {
		h.callbackError(c, err)
		return
	}
	if old, err := h.readCookie(c, false); err == nil {
		if err := h.Flow.Store.RevokeSession(c.Request.Context(), identity.CentralSecretDigest(old), time.Now().UTC()); err != nil {
			h.callbackError(c, err)
			return
		}
	}
	h.cookie(c, false, result.Secret, result.Session.ExpiresAt)
	c.Redirect(http.StatusFound, "/auth/central/callback")
}

// Session bootstraps browser memory from current cookie and fresh authority
// status. Profile hydration uses the same local reader as the existing current
// user endpoint, preserving group restrictions and avatar metadata after reload.
func (h *CentralHandler) Session(c *gin.Context) {
	centralNoStore(c)
	if !h.enabled(c) || !h.browserOrigin(c, false) {
		return
	}
	verified, ok := h.authenticate(c)
	if !ok {
		return
	}
	user, err := h.Users.GetByID(c.Request.Context(), verified.User.ID)
	if err != nil {
		centralHTTPError(c, identity.ErrCentralUnavailable)
		return
	}
	if !user.IsActive() || !user.CentralManaged {
		centralHTTPError(c, identity.ErrCentralAccountInactive)
		return
	}
	identities, err := h.Users.GetProfileIdentitySummaries(c.Request.Context(), user.ID, user)
	if err != nil {
		centralHTTPError(c, identity.ErrCentralUnavailable)
		return
	}
	response.Success(c, gin.H{"user": UserProfileResponseFromService(user, identities), "csrf_token": verified.Session.CSRFSecret, "expires_at": verified.Session.ExpiresAt, "auth_mode": "central"})
}

// Logout revokes this local browser session without requiring a live identity provider.
// It never emits cookie deletion that could erase a later concurrently established session.
func (h *CentralHandler) Logout(c *gin.Context) { h.logout(c, false) }

// RevokeAll revokes this local user's human sessions without changing machine API keys.
func (h *CentralHandler) RevokeAll(c *gin.Context) { h.logout(c, true) }

// logout verifies the separate CSRF secret against persisted original session evidence.
// Expiry or upstream suspension does not prevent withdrawal of local sessions.
func (h *CentralHandler) logout(c *gin.Context, all bool) {
	centralNoStore(c)
	if !h.enabled(c) || !h.browserOrigin(c, true) {
		return
	}
	if c.GetHeader("Authorization") != "" {
		centralHTTPError(c, identity.ErrCentralEvidenceInvalid)
		return
	}
	raw, err := h.readCookie(c, false)
	if err != nil {
		centralHTTPError(c, err)
		return
	}
	session, err := h.Flow.Store.ReadSession(c.Request.Context(), identity.CentralSecretDigest(raw))
	if err != nil {
		centralHTTPError(c, err)
		return
	}
	if !identity.CentralCSRFMatches(session, c.GetHeader("X-CSRF-Token")) {
		centralHTTPError(c, identity.ErrCentralProofRequired)
		return
	}
	if all {
		err = h.Flow.Store.RevokeUserSessions(c.Request.Context(), session.LocalUserID, time.Now().UTC())
	} else {
		err = h.Flow.Store.RevokeSession(c.Request.Context(), session.Digest, time.Now().UTC())
	}
	if err != nil {
		centralHTTPError(c, err)
		return
	}
	response.Success(c, gin.H{"revoked": true})
}

// Wrap selects central cookie admission before an existing human-authentication guard.
// The separate machine-token middleware remains outside this wrapper in composition.
func (h *CentralHandler) Wrap(legacy gin.HandlerFunc, administrator bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !h.HasCookie(c) {
			legacy(c)
			return
		}
		// An explicit legacy credential can follow a completed central logout.
		// Only a durable inert-cookie observation permits that selection; unknown,
		// live or unavailable session state cannot silently downgrade authentication.
		if h.Flow != nil && c.GetHeader("Authorization") != "" {
			raw, readErr := h.readCookie(c, false)
			if readErr == nil {
				saved, stateErr := h.Flow.Store.ReadSession(c.Request.Context(), identity.CentralSecretDigest(raw))
				if stateErr == nil && (saved.RevokedAt != nil || !time.Now().Before(saved.ExpiresAt)) {
					legacy(c)
					return
				}
			}
		}
		centralNoStore(c)
		if !h.enabled(c) || !h.browserOrigin(c, !centralSafeMethod(c.Request.Method)) {
			return
		}
		verified, ok := h.authenticate(c)
		if !ok {
			return
		}
		// A stale legacy tab can lose shared localStorage while retaining its old
		// user view. Requiring the current session proof on reads too prevents the
		// new cookie from silently changing that tab's authenticated owner.
		if !identity.CentralCSRFMatches(verified.Session, c.GetHeader("X-CSRF-Token")) {
			centralHTTPError(c, identity.ErrCentralProofRequired)
			return
		}
		required := identity.CentralAccessOrdinary
		if h.Options.Access != nil {
			var err error
			required, err = h.Options.Access(c.Request.Context(), verified.User.ID, c.FullPath(), c.Request.Method)
			if err != nil {
				centralHTTPError(c, err)
				return
			}
		}
		if administrator {
			required = identity.CentralAccessSensitive
		}
		if err := identity.AuthorizeCentralSession(h.Flow.Options.Policy, verified.Session, verified.Status, verified.RequestStartedAt, time.Now().UTC(), required); err != nil {
			centralHTTPError(c, err)
			return
		}
		if administrator && verified.User.Role != "admin" {
			AbortWithError(c, http.StatusForbidden, "FORBIDDEN", "Administrator access required")
			return
		}
		authctx.SetPrincipal(c, identity.Principal{UserID: verified.User.ID, Role: verified.User.Role, SessionID: verified.Session.Digest, CredentialKind: "central"}, verified.User.Concurrency, verified.User.Email)
		authctx.SetCentralAccess(c, func(required identity.CentralAccessClass) error {
			return identity.AuthorizeCentralSession(h.Flow.Options.Policy, verified.Session, verified.Status, verified.RequestStartedAt, time.Now().UTC(), required)
		})
		c.Set(centralAuthenticatedKey, verified)
		c.Next()
	}
}

// HasCookie recognizes both known names so disabling a profile cannot silently select legacy auth.
func (h *CentralHandler) HasCookie(c *gin.Context) bool {
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == centralSessionCookie || cookie.Name == centralTestSessionCookie {
			return true
		}
	}
	return false
}

// authenticate rejects mixed identities before resolving one bounded browser credential.
func (h *CentralHandler) authenticate(c *gin.Context) (identity.CentralAuthenticated, bool) {
	if c.GetHeader("Authorization") != "" {
		centralHTTPError(c, identity.ErrCentralEvidenceInvalid)
		return identity.CentralAuthenticated{}, false
	}
	raw, err := h.readCookie(c, false)
	if err != nil {
		centralHTTPError(c, err)
		return identity.CentralAuthenticated{}, false
	}
	verified, err := h.Flow.Authenticate(c.Request.Context(), raw)
	if err != nil {
		centralHTTPError(c, err)
		return identity.CentralAuthenticated{}, false
	}
	if supplied := c.GetHeader("X-CSRF-Token"); supplied != "" && !identity.CentralCSRFMatches(verified.Session, supplied) {
		centralHTTPError(c, identity.ErrCentralProofRequired)
		return identity.CentralAuthenticated{}, false
	}
	return verified, true
}

// enabled denies disabled shared authentication without falling back to local credentials.
func (h *CentralHandler) enabled(c *gin.Context) bool {
	if h.Flow != nil {
		return true
	}
	centralHTTPError(c, identity.ErrCentralUnavailable)
	return false
}

// browserOrigin requires exact-origin mutations and rejects cross-origin browser reads.
// Missing Origin on safe navigation or non-browser reads does not grant mutation access.
func (h *CentralHandler) browserOrigin(c *gin.Context, mutation bool) bool {
	origin, err := url.Parse(h.Options.Origin)
	if err != nil || c.Request.Host != origin.Host || mutation && c.GetHeader("Origin") != h.Options.Origin || c.GetHeader("Origin") != "" && c.GetHeader("Origin") != h.Options.Origin || c.GetHeader("Sec-Fetch-Site") == "cross-site" || c.GetHeader("Sec-Fetch-Site") == "same-site" {
		AbortWithError(c, http.StatusForbidden, "CENTRAL_ORIGIN_REQUIRED", "This operation requires the configured application origin")
		return false
	}
	return true
}

// readCookie rejects ambiguous duplicate or cross-profile cookie names.
func (h *CentralHandler) readCookie(c *gin.Context, login bool) (string, error) {
	wanted := centralSessionCookie
	alternate := centralTestSessionCookie
	if login {
		wanted, alternate = centralLoginCookie, centralTestLoginCookie
	}
	if h.Options.TestLoopback {
		wanted, alternate = alternate, wanted
	}
	value, count := "", 0
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == alternate {
			return "", identity.ErrCentralEvidenceInvalid
		}
		if cookie.Name == wanted {
			value, count = cookie.Value, count+1
		}
	}
	if count != 1 || len(value) != 64 {
		return "", identity.ErrCentralSessionExpired
	}
	return value, nil
}

// cookie writes only host-only, HttpOnly, Lax cookies with finite absolute expiration.
func (h *CentralHandler) cookie(c *gin.Context, login bool, value string, expires time.Time) {
	name := centralSessionCookie
	if login {
		name = centralLoginCookie
	}
	if h.Options.TestLoopback {
		name = centralTestSessionCookie
		if login {
			name = centralTestLoginCookie
		}
	}
	maxAge := -1
	if value != "" {
		maxAge = max(1, int(time.Until(expires).Seconds()))
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: name, Value: value, Path: "/", Secure: !h.Options.TestLoopback, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: maxAge})
}

// callbackError maps sensitive failures to a fixed frontend route and finite public reason.
func (h *CentralHandler) callbackError(c *gin.Context, err error) {
	reason := "authentication_failed"
	switch {
	case errors.Is(err, identity.ErrCentralNotBound):
		reason = "account_not_linked"
	case errors.Is(err, identity.ErrCentralConflict), errors.Is(err, identity.ErrEmailExists):
		reason = "account_conflict"
	case errors.Is(err, identity.ErrCentralUnavailable):
		reason = "temporarily_unavailable"
	case errors.Is(err, identity.ErrCentralAccountInactive), errors.Is(err, identity.ErrCentralProofRequired), errors.Is(err, identity.ErrCentralBindingDisabled):
		reason = "access_denied"
	}
	c.Redirect(http.StatusFound, "/auth/central/callback?error="+reason)
}

// centralNoStore prevents browser and intermediary caching of authentication responses.
func centralNoStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Vary", "Cookie, Origin")
}

// centralSafeMethod identifies requests that never receive mutation authority from cookies alone.
func centralSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// centralHTTPError preserves retryable outages separately from authentication and assurance denial.
func centralHTTPError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, identity.ErrCentralUnavailable), errors.Is(err, identity.ErrCentralEvidenceStale):
		AbortWithError(c, http.StatusServiceUnavailable, "CENTRAL_UNAVAILABLE", "Shared authentication is temporarily unavailable")
	case errors.Is(err, identity.ErrCentralProofRequired), errors.Is(err, identity.ErrCentralBindingDisabled):
		AbortWithError(c, http.StatusForbidden, "CENTRAL_PROOF_REQUIRED", "Additional account verification is required for this action.")
	case errors.Is(err, identity.ErrCentralConflict):
		AbortWithError(c, http.StatusConflict, "CENTRAL_ACCOUNT_CONFLICT", "This identity cannot be attached to the selected account")
	default:
		AbortWithError(c, http.StatusUnauthorized, "CENTRAL_AUTHENTICATION_REQUIRED", "Shared sign-in is required")
	}
}
