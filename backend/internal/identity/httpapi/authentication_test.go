package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// authentication_test.go checks withdrawal dispatch when a browser retains an
// inert central cookie and later uses a legacy account. The real session
// service and JWT middleware run against recording persistence ports, so HTTP
// success alone cannot stand in for refresh-token revocation. Distinct legacy
// and central owners expose accidental account switching during dispatch.

// authenticationRefreshProbe records the actual legacy credential withdrawal target.
type authenticationRefreshProbe struct {
	identity.RefreshTokenCache          // unrelated issuance operations remain unavailable
	deletedHashes              []string // submitted refresh credentials after hashing
	revokedUsers               []int64  // authenticated legacy owners selected for withdrawal
}

// authenticationUserProbe exposes current ownership to the real JWT middleware.
type authenticationUserProbe struct {
	identity.UserRepository                // unrelated account operations remain unavailable
	user                    *identity.User // mutable current legacy account snapshot
	reads                   int            // fresh account lookups performed by production rules
}

// authenticationWithdrawalFixture retains real handlers and independently owned session facts.
type authenticationWithdrawalFixture struct {
	handler *AuthenticationHandler      // assembled production withdrawal dispatch
	store   *centralHTTPStoreProbe      // original central owner and session observation
	refresh *authenticationRefreshProbe // legacy credential revocation recorder
	users   *authenticationUserProbe    // current independent legacy account reader
	token   string                      // real signed legacy access credential
	secret  string                      // retained opaque central cookie value
	csrf    string                      // central session request-binding secret
}

// DeleteRefreshToken records the digest received from the real session service.
// Observing this call distinguishes actual legacy withdrawal dispatch from a
// handler that returns success without reaching credential persistence.
func (p *authenticationRefreshProbe) DeleteRefreshToken(_ context.Context, digest string) error {
	p.deletedHashes = append(p.deletedHashes, digest)
	return nil
}

// DeleteUserRefreshTokens records the authenticated owner selected for legacy
// withdrawal. The fixture keeps this target separate from the central cookie's
// owner so a confused dispatch cannot appear successful.
func (p *authenticationRefreshProbe) DeleteUserRefreshTokens(_ context.Context, userID int64) error {
	p.revokedUsers = append(p.revokedUsers, userID)
	return nil
}

// GetByID supplies a fresh copy of the configured legacy owner for each call.
// Changing its durable central-management flag after token issuance must reach
// JWT validation before account-wide withdrawal proceeds.
func (p *authenticationUserProbe) GetByID(_ context.Context, userID int64) (*identity.User, error) {
	p.reads++
	if userID != p.user.ID {
		return nil, identity.ErrUserNotFound
	}
	user := *p.user
	user.TokenVersion = identity.ResolvedTokenVersion(&user)
	return &user, nil
}

// newAuthenticationWithdrawalFixture constructs real dispatch and session
// services with distinct central and legacy owners. Only persistence and
// authority observation are fixtures; the JWT is signed and validated by the
// production implementation.
func newAuthenticationWithdrawalFixture(t *testing.T) *authenticationWithdrawalFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy := identity.CentralConsumerPolicy{ConsumerID: "gettok", AuthorityIncarnation: "authority-test", OrdinaryPolicyID: "gettok-ordinary-login", OrdinaryPolicyVersion: 1}
	status := identity.CentralStatusEvidence{Account: identity.CentralAccountReference{AccountID: "original-central-owner", AuthorityIncarnation: policy.AuthorityIncarnation}, ConsumerID: policy.ConsumerID, Eligibility: identity.CentralEligibilityActive, Revision: 1, SecurityEpoch: 1, AttachmentGeneration: 1, ObservedAt: now, ValidUntil: now.Add(identity.CentralSourceLease)}
	secret, csrf := strings.Repeat("a", 64), strings.Repeat("b", 64)
	session := identity.CentralSession{Digest: identity.CentralSecretDigest(secret), CSRFSecret: csrf, LocalUserID: 7, Account: status.Account, SecurityEpoch: 1, AttachmentGeneration: 1, CreatedAt: now, ExpiresAt: now.Add(4 * time.Minute), Admission: identity.CentralSessionAdmission{AuthoritySessionID: "verified-kc-session", Profile: identity.CentralProfileProviderSession, PolicyID: policy.OrdinaryPolicyID, PolicyVersion: 1, AuthenticatedAt: now.Add(-time.Minute), ValidUntil: now.Add(4 * time.Minute)}}
	store := &centralHTTPStoreProbe{session: session, status: status, user: &identity.User{ID: 7, Status: "active", Role: "user", CentralManaged: true}}
	central := &CentralHandler{Options: CentralHTTPOptions{Origin: "http://127.0.0.1:18182", TestLoopback: true}, Flow: &identity.CentralFlow{Options: identity.CentralLoginOptions{Policy: policy}, Store: store, Authority: &centralHTTPAuthorityProbe{status: status}, Now: func() time.Time { return now }}}
	users := &authenticationUserProbe{user: &identity.User{ID: 41, Email: "legacy@example.test", PasswordHash: "fixture-password-hash", Status: "active", Role: "user"}}
	refresh := &authenticationRefreshProbe{}
	auth := identity.NewAuthService(&identity.AuthDependencies{Users: users, RefreshTokens: refresh, Options: &identity.AuthOptions{JWT: identity.SessionOptions{Secret: strings.Repeat("fixture-", 8), ExpireHour: 1, Now: func() time.Time { return now }}}}, nil)
	token, err := auth.GenerateToken(t.Context(), users.user)
	require.NoError(t, err)
	handler := &AuthenticationHandler{Central: central, Session: NewSessionHandler(auth, nil, nil, nil, nil, nil, SessionHTTPOptions{})}
	return &authenticationWithdrawalFixture{handler: handler, store: store, refresh: refresh, users: users, token: token, secret: secret, csrf: csrf}
}

// TestAuthenticationLogoutWithRetainedCentralCookie checks actual refresh-token
// withdrawal after central logout or expiry, with and without a legacy access
// token. Live, unknown and unreadable cookies retain central proof checks and
// cannot invoke legacy credential persistence.
func TestAuthenticationLogoutWithRetainedCentralCookie(t *testing.T) {
	for _, row := range []struct {
		name          string // persisted cookie state for the withdrawal attempt
		bearerStatus  int    // response when a legacy access token is also supplied
		refreshStatus int    // response for refresh-only legacy withdrawal
	}{
		{"revoked", http.StatusOK, http.StatusOK},
		{"expired", http.StatusOK, http.StatusOK},
		{"live", http.StatusUnauthorized, http.StatusForbidden},
		{"unknown", http.StatusUnauthorized, http.StatusUnauthorized},
		{"read_failure", http.StatusUnauthorized, http.StatusServiceUnavailable},
	} {
		for _, credential := range []string{"access_and_refresh", "refresh_only"} {
			t.Run(row.name+"/"+credential, func(t *testing.T) {
				fixture := newAuthenticationWithdrawalFixture(t)
				now := time.Now().UTC()
				switch row.name {
				case "revoked":
					fixture.store.session.RevokedAt = &now
				case "expired":
					fixture.store.session.ExpiresAt = now.Add(-time.Minute)
				case "unknown":
					fixture.store.readErr = identity.ErrCentralSessionExpired
				case "read_failure":
					fixture.store.readErr = identity.ErrCentralUnavailable
				}
				refresh := identity.RefreshTokenPrefix + "withdrawal-fixture"
				engine := gin.New()
				engine.POST("/api/v1/auth/logout", fixture.handler.Logout)
				request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18182/api/v1/auth/logout", strings.NewReader(`{"refresh_token":"`+refresh+`"}`))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Origin", "http://127.0.0.1:18182")
				status := row.refreshStatus
				if credential == "access_and_refresh" {
					request.Header.Set("Authorization", "Bearer "+fixture.token)
					status = row.bearerStatus
				}
				request.AddCookie(&http.Cookie{Name: centralTestSessionCookie, Value: fixture.secret})
				response := httptest.NewRecorder()
				engine.ServeHTTP(response, request)
				require.Equal(t, status, response.Code)
				if status == http.StatusOK {
					require.Equal(t, []string{identity.HashToken(refresh)}, fixture.refresh.deletedHashes)
				} else {
					require.Empty(t, fixture.refresh.deletedHashes)
				}
				require.Empty(t, fixture.store.revokedUsers)
			})
		}
	}
}

// TestAuthenticationRevokeAllUsesCurrentPrincipal preserves owner selection
// after real JWT or central middleware admission. A retained cookie cannot
// redirect legacy withdrawal, and a newly managed owner cannot reuse an older JWT.
func TestAuthenticationRevokeAllUsesCurrentPrincipal(t *testing.T) {
	for _, row := range []struct {
		name   string // account and cookie admission scenario
		status int    // expected response after the real authentication wrapper
	}{
		{"revoked_legacy", http.StatusOK},
		{"expired_legacy", http.StatusOK},
		{"managed_legacy", http.StatusUnauthorized},
		{"live_mixed", http.StatusUnauthorized},
		{"central", http.StatusOK},
	} {
		t.Run(row.name, func(t *testing.T) {
			fixture := newAuthenticationWithdrawalFixture(t)
			now := time.Now().UTC()
			switch row.name {
			case "revoked_legacy", "managed_legacy":
				fixture.store.session.RevokedAt = &now
			case "expired_legacy":
				fixture.store.session.ExpiresAt = now.Add(-time.Minute)
			}
			fixture.users.user.CentralManaged = row.name == "managed_legacy"
			legacy := JWTAuth(fixture.handler.Session.authService, fixture.users, nil, nil, nil)
			engine := gin.New()
			engine.POST("/api/v1/auth/revoke-all-sessions", fixture.handler.Central.Wrap(legacy, false), fixture.handler.RevokeAllSessions)
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18182/api/v1/auth/revoke-all-sessions", nil)
			request.Header.Set("Origin", "http://127.0.0.1:18182")
			request.Header.Set("X-CSRF-Token", fixture.csrf)
			if row.name != "central" {
				request.Header.Set("Authorization", "Bearer "+fixture.token)
			}
			request.AddCookie(&http.Cookie{Name: centralTestSessionCookie, Value: fixture.secret})
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)
			require.Equal(t, row.status, response.Code)
			if row.name == "central" {
				require.Equal(t, []int64{7}, fixture.store.revokedUsers)
				require.Empty(t, fixture.refresh.revokedUsers)
			} else if row.status == http.StatusOK {
				require.Equal(t, []int64{41}, fixture.refresh.revokedUsers)
				require.Empty(t, fixture.store.revokedUsers)
				require.GreaterOrEqual(t, fixture.users.reads, 2)
			} else {
				require.Empty(t, fixture.refresh.revokedUsers)
				require.Empty(t, fixture.store.revokedUsers)
			}
		})
	}
}
