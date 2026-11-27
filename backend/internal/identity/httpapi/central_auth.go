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
// A live or unobserved central cookie precedes legacy Bearer authentication,
// and mixed credentials are rejected. A durably revoked or expired cookie
// permits an explicit legacy Bearer to reach its existing guard.
// Protected reads and mutations require the
// session's CSRF secret, preventing another tab's cookie from silently changing
// the displayed owner. Mutations also require the configured exact origin;
// the dedicated session bootstrap permits the initial proof-free same-origin read.
// Logout persists local revocation and leaves an inert cookie to expire, so a
// delayed response cannot erase a newer login. It remains usable during an
// upstream outage. Only an explicit loopback TEST configuration uses
// non-Secure cookies, under names distinct from the production host cookies.

// These cookie names keep the production host boundary distinct from explicit
// loopback TEST sessions; the context key carries one verified request snapshot.
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

// RegisterCentralAuthenticationRoutes mounts the optional shared browser flow
// inside the existing authentication boundary. A nil handler leaves routes
// absent; composition supplies audit, backend-mode and fail-closed rate
// middleware.
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

// Config exposes browser labels and currently available login capabilities
// without disclosing endpoints or client credentials. Backend mode disables
// new shared login, and the migration flag reflects only the explicitly
// enabled TEST profile.
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

// Start validates the configured browser origin and decodes one bounded
// explicit account intent. Anonymous login and registration retain the
// existing CAPTCHA gate, while TEST binding requires a current legacy session
// plus fresh password and enrolled-factor proof. Mixed identity inputs and
// unknown JSON fields are rejected before creating a transaction. Only after
// the encrypted intent is persisted does the response set its browser binding
// cookie and return the configured provider authorization URL.
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
		// A retained cookie permits binding only after durable revocation or expiry.
		// It cannot replace the legacy bearer, password or enrolled-factor checks below.
		if h.Flow.Options.TestBindingProfile != identity.CentralTestBindingProfile || h.HasCookie(c) && !h.hasInertCookie(c) {
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

// Callback finishes one browser-bound transaction and exposes the new session
// only after its local commit. It accepts a single code and state, rejects a
// contradictory issuer or mixed Bearer credential, and consumes the
// transaction before provider exchange. A known previous cookie is revoked
// before publishing its replacement. The response redirects to a fixed
// frontend route with a finite error category; failed exchanges never return
// provider diagnostics or credentials to that route.
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

// RevokeAll withdraws this local user's human browser sessions after the
// normal logout proof checks. It leaves machine API keys and central lifecycle
// state to their separately owned authorization paths.
func (h *CentralHandler) RevokeAll(c *gin.Context) { h.logout(c, true) }

// logout verifies exact browser origin and the separate CSRF secret against
// persisted original session evidence. Expiry or upstream suspension does not
// prevent withdrawal of local sessions, because logout does not depend on a
// fresh authority call. Database failure remains an error, and the response
// reports success only after revocation commits. It leaves the cookie to
// expire naturally so a delayed logout response cannot delete a newer session
// created by another login.
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

// Wrap selects central cookie admission before the existing human
// authentication guard and leaves machine-token authentication to composition.
// A live or unknown cookie cannot silently downgrade to a supplied legacy
// credential; only a durable revoked or expired session permits that explicit
// fallback. Protected reads also require the session's memory-held proof,
// preventing an old tab from accepting another tab's newly issued cookie as
// its own account.
//
// After fresh admission, the wrapper applies route assurance and local
// administrator checks, then installs a verifier capturing the original
// session evidence. Resource handlers must still decide product ownership and
// roles before returning or changing their selected resource.
func (h *CentralHandler) Wrap(legacy gin.HandlerFunc, administrator bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !h.HasCookie(c) {
			legacy(c)
			return
		}
		// An explicit legacy credential can follow a completed central logout.
		// Only a durable inert-cookie observation permits that selection; unknown,
		// live or unavailable session state cannot silently downgrade authentication.
		if c.GetHeader("Authorization") != "" && h.hasInertCookie(c) {
			legacy(c)
			return
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

// HasCookie recognizes both production and explicit TEST session-cookie names.
// This selection remains independent of the active profile so disabling shared
// authentication cannot silently route a previously central session through
// legacy authentication.
func (h *CentralHandler) HasCookie(c *gin.Context) bool {
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == centralSessionCookie || cookie.Name == centralTestSessionCookie {
			return true
		}
	}
	return false
}

// hasInertCookie reports whether storage confirms that a retained central
// cookie names a revoked or expired session. Missing cookies, unknown rows,
// read failures and live sessions cannot establish that observation.
//
// Authentication middleware still requires an explicit legacy Authorization
// header before selecting its existing credential checks. Public logout uses
// the same durable observation to preserve optional refresh-token withdrawal
// without requiring an access token. TEST binding still performs its complete
// legacy-owner verification after this observation. This decision grants no authentication
// or product authority, and a disabled flow cannot establish an inert session.
func (h *CentralHandler) hasInertCookie(c *gin.Context) bool {
	if h.Flow == nil {
		return false
	}
	raw, err := h.readCookie(c, false)
	if err != nil {
		return false
	}
	session, err := h.Flow.Store.ReadSession(c.Request.Context(), identity.CentralSecretDigest(raw))
	return err == nil && (session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt))
}

// authenticate rejects mixed Bearer and cookie identities before resolving a
// bounded browser credential. A supplied CSRF proof must match; only the
// dedicated bootstrap caller may proceed without one.
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

// enabled reports whether startup supplied a shared authentication flow.
// A disabled flow returns the explicit CENTRAL_DISABLED code, allowing browser
// startup to distinguish a disabled capability from an enabled service outage.
// Requests carrying a central cookie still remain on this handler's refusal path.
func (h *CentralHandler) enabled(c *gin.Context) bool {
	if h.Flow != nil {
		return true
	}
	AbortWithError(c, http.StatusServiceUnavailable, "CENTRAL_DISABLED", "Shared identity is disabled")
	return false
}

// browserOrigin validates the effective application Host and any supplied
// Origin before cookie-authenticated work. Mutations require the exact
// configured Origin; safe reads may omit it for ordinary same-origin
// navigation or non-browser clients. Explicit cross-site and sibling-site
// fetch metadata remains rejected even when cookies would otherwise be sent.
// This check establishes browser provenance only: protected resources
// separately require the current session proof, while initial bootstrap has
// its own limited proof-free entry.
func (h *CentralHandler) browserOrigin(c *gin.Context, mutation bool) bool {
	origin, err := url.Parse(h.Options.Origin)
	if err != nil || c.Request.Host != origin.Host || mutation && c.GetHeader("Origin") != h.Options.Origin || c.GetHeader("Origin") != "" && c.GetHeader("Origin") != h.Options.Origin || c.GetHeader("Sec-Fetch-Site") == "cross-site" || c.GetHeader("Sec-Fetch-Site") == "same-site" {
		AbortWithError(c, http.StatusForbidden, "CENTRAL_ORIGIN_REQUIRED", "This operation requires the configured application origin")
		return false
	}
	return true
}

// readCookie selects the expected session or transaction cookie for the
// configured transport profile. Duplicate names, the alternate profile's
// cookie, and missing or incorrectly sized values fail before any authority
// lookup.
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

// cookie writes the opaque session or transaction value with host-only,
// HttpOnly and Lax attributes. Production uses Secure prefixed names, while
// explicitly enabled loopback TEST transport uses different names without
// Secure. The caller supplies the already bounded absolute expiration;
// converting the remaining interval to whole seconds does not extend server
// admission. Empty values clear the selected cookie; the callback uses this
// for its transaction cookie. Logout leaves the session cookie untouched.
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

// callbackError maps authentication failures to a fixed frontend destination
// and a finite public reason. It never copies upstream diagnostics or accepts
// a browser-selected return destination that could receive callback
// credentials.
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

// centralHTTPError preserves retryable outages separately from invalid
// authentication and insufficient assurance. Stable public categories let the
// browser retain an ordinary session on a stronger-proof refusal without
// exposing provider or persistence diagnostics.
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
