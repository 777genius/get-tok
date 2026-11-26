package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
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

// TestCentralCookieCustody keeps production and TEST cookies visibly distinct.
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

// TestCentralOriginRejectsCrossSiteMutation verifies the exact browser origin and host.
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
