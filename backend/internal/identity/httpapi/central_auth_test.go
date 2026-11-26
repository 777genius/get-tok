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

// central_auth_test.go checks the browser boundary independently of network
// provider fixtures. The tests inspect real Set-Cookie headers and invoke the
// same origin gate used before browser mutations. They distinguish production
// host cookies from the explicitly named loopback TEST transport so a successful
// local HTTP scenario cannot stand in for verified production cookie attributes.
//
// Full callback and database revocation behavior is exercised separately with
// native PostgreSQL and the actual Identity/Keycloak profile. These small tests
// focus on browser properties that a server-side cookie jar cannot establish:
// HttpOnly, host-only scope, Secure production transport and rejection of
// cross-site or same-site sibling origins before application state changes.

// centralHTTPStoreProbe returns one already committed owner for middleware scenarios.
type centralHTTPStoreProbe struct {
	identity.CentralSessionStore                                // unused writes fail if a read-only guard invokes them
	session                      identity.CentralSession        // immutable session issued to the replacement tab
	status                       identity.CentralStatusEvidence // fresh authority observation
	user                         *identity.User                 // current active owner for the opaque cookie
}

// centralHTTPAuthorityProbe supplies only the fresh read used by this middleware test.
type centralHTTPAuthorityProbe struct {
	identity.CentralIdentityAuthority                                // human resolution is outside this guard scenario
	status                            identity.CentralStatusEvidence // fresh observation of the replacement owner
}

// ReadSession returns the original persisted session before authority observation.
func (p *centralHTTPStoreProbe) ReadSession(context.Context, string) (identity.CentralSession, error) {
	return p.session, nil
}

// PublishAndRead supplies the unchanged committed facts after a successful fresh read.
func (p *centralHTTPStoreProbe) PublishAndRead(context.Context, string, identity.CentralStatusEvidence) (identity.CentralSession, identity.CentralStatusEvidence, *identity.User, error) {
	return p.session, p.status, p.user, nil
}

// GetAccountStatus returns the independently authenticated observation for the fixture.
func (p *centralHTTPAuthorityProbe) GetAccountStatus(context.Context, identity.CentralAccountReference) (identity.CentralStatusEvidence, error) {
	return p.status, nil
}

// TestCentralProtectedReadsRequireSessionProof rejects a legacy tab whose shared
// storage was cleared while another tab acquired a new HttpOnly cookie. A valid
// cookie alone must not load a replacement owner's profile into the stale view.
func TestCentralProtectedReadsRequireSessionProof(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy := identity.CentralConsumerPolicy{ConsumerID: "gettok", AuthorityIncarnation: "authority-test", OrdinaryPolicyID: "gettok-ordinary-login", OrdinaryPolicyVersion: 1}
	status := identity.CentralStatusEvidence{Account: identity.CentralAccountReference{AccountID: "replacement-owner", AuthorityIncarnation: policy.AuthorityIncarnation}, ConsumerID: policy.ConsumerID, Eligibility: identity.CentralEligibilityActive, Revision: 1, SecurityEpoch: 1, AttachmentGeneration: 1, ObservedAt: now, ValidUntil: now.Add(identity.CentralSourceLease)}
	secret, csrf := strings.Repeat("a", 64), strings.Repeat("b", 64)
	session := identity.CentralSession{Digest: identity.CentralSecretDigest(secret), CSRFSecret: csrf, LocalUserID: 7, Account: status.Account, SecurityEpoch: 1, AttachmentGeneration: 1, CreatedAt: now, ExpiresAt: now.Add(4 * time.Minute), Admission: identity.CentralSessionAdmission{AuthoritySessionID: "verified-kc-session", Profile: identity.CentralProfileProviderSession, PolicyID: policy.OrdinaryPolicyID, PolicyVersion: 1, AuthenticatedAt: now.Add(-time.Minute), ValidUntil: now.Add(4 * time.Minute)}}
	store := &centralHTTPStoreProbe{session: session, status: status, user: &identity.User{ID: 7, Status: "active", Role: "user", CentralManaged: true}}
	handler := &CentralHandler{Options: CentralHTTPOptions{Origin: "http://127.0.0.1:18182", TestLoopback: true}, Flow: &identity.CentralFlow{Options: identity.CentralLoginOptions{Policy: policy}, Store: store, Authority: &centralHTTPAuthorityProbe{status: status}, Now: func() time.Time { return now }}}
	for _, row := range []struct {
		proof  string // memory-held session proof, absent in a stale legacy tab
		status int    // expected refusal before the protected profile handler
	}{{"", http.StatusForbidden}, {strings.Repeat("c", 64), http.StatusForbidden}, {csrf, http.StatusOK}} {
		profileReads, legacyCalls := 0, 0
		engine := gin.New()
		engine.GET("/api/v1/auth/me", handler.Wrap(func(c *gin.Context) { legacyCalls++; c.AbortWithStatus(http.StatusUnauthorized) }, false), func(c *gin.Context) { profileReads++; c.Status(http.StatusOK) })
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18182/api/v1/auth/me", nil)
		request.AddCookie(&http.Cookie{Name: centralTestSessionCookie, Value: secret})
		request.Header.Set("X-CSRF-Token", row.proof)
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		require.Equal(t, row.status, response.Code)
		require.Zero(t, legacyCalls)
		if row.status == http.StatusOK {
			require.Equal(t, 1, profileReads)
		} else {
			require.Zero(t, profileReads)
		}
	}
}

// TestCentralCookieCustody exercises both transaction and session cookies in
// production and loopback TEST profiles. Browser attributes must retain their
// distinct Secure boundary, HttpOnly custody and finite expiration.
func TestCentralCookieCustody(t *testing.T) {
	for _, testLoopback := range []bool{false, true} {
		for _, login := range []bool{false, true} {
			writer := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(writer)
			handler := &CentralHandler{Options: CentralHTTPOptions{TestLoopback: testLoopback}}
			handler.cookie(context, login, strings.Repeat("a", 64), time.Now().Add(4*time.Minute))
			cookies := writer.Result().Cookies()
			require.Len(t, cookies, 1)
			cookie := cookies[0]
			require.Equal(t, !testLoopback, cookie.Secure)
			require.True(t, cookie.HttpOnly)
			require.Empty(t, cookie.Domain)
			require.Equal(t, "/", cookie.Path)
			require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			require.Positive(t, cookie.MaxAge)
			require.LessOrEqual(t, cookie.MaxAge, 240)
			require.Equal(t, !testLoopback, strings.HasPrefix(cookie.Name, "__Host-"))
		}
	}
}

// TestCentralOriginRejectsCrossSiteMutation varies Origin, Host and fetch-site
// metadata around the configured browser endpoint. Cross-site and sibling-site
// requests must fail before any application operation can run.
func TestCentralOriginRejectsCrossSiteMutation(t *testing.T) {
	for _, row := range []struct {
		origin   string // supplied Origin header
		site     string // browser fetch-site observation
		host     string // effective application host
		mutation bool   // operation can change application state
		allowed  bool   // expected admission before any store call
	}{
		{"https://app.example.test", "same-origin", "app.example.test", true, true},
		{"", "same-origin", "app.example.test", true, false},
		{"https://sibling.example.test", "same-site", "app.example.test", true, false},
		{"https://app.example.test", "cross-site", "app.example.test", true, false},
		{"https://app.example.test", "same-origin", "other.example.test", true, false},
		{"", "same-origin", "app.example.test", false, true},
		{"", "cross-site", "app.example.test", false, false},
	} {
		writer := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(writer)
		context.Request = httptest.NewRequest(http.MethodPost, "https://"+row.host+"/api/v1/auth/central/start", nil)
		context.Request.Header.Set("Origin", row.origin)
		context.Request.Header.Set("Sec-Fetch-Site", row.site)
		handler := &CentralHandler{Options: CentralHTTPOptions{Origin: "https://app.example.test"}}
		require.Equal(t, row.allowed, handler.browserOrigin(context, row.mutation))
		if !row.allowed {
			require.Equal(t, http.StatusForbidden, writer.Code)
		}
	}
}
