//go:build integration && native_identity

package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	dbent "github.com/TokenFlux/TokenRouter/ent"
	"github.com/TokenFlux/TokenRouter/internal/config"
	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/identity/authconfig"
	identityhttp "github.com/TokenFlux/TokenRouter/internal/identity/httpapi"
	identitypostgres "github.com/TokenFlux/TokenRouter/internal/identity/postgres"
	cryptoinfra "github.com/TokenFlux/TokenRouter/internal/infra/crypto"
	"github.com/TokenFlux/TokenRouter/internal/pkg/timezone"
	"github.com/TokenFlux/TokenRouter/internal/server/httpconfig"
	"github.com/TokenFlux/TokenRouter/internal/server/middleware"
	"github.com/TokenFlux/TokenRouter/internal/settings"
	settingspostgres "github.com/TokenFlux/TokenRouter/internal/settings/postgres"
	"github.com/TokenFlux/TokenRouter/internal/testutil/postgrescontainer"
	"github.com/TokenFlux/TokenRouter/internal/web"
)

// identity_central_integration_test.go joins the production GetTok BFF
// with a real Identity HTTP server, Keycloak authorization-code flow and migrated
// PostgreSQL storage. The explicitly selected native_identity tag requires all
// native dependencies; absent configuration fails instead of silently reducing
// this qualification to mocked ports. The surrounding runner starts and stops
// the isolated authorities and provides separately scoped disposable credentials.
//
// HTTP registration establishes one local owner before the real browser opens
// the built frontend through the production SPA middleware. Browser execution
// receives argv as JSON without a shell. After its independent login and logout,
// a production Identity lifecycle command suspends the account, and the original
// HTTP cookie must immediately fail fresh admission. These tests qualify only
// ordinary TEST admission and do not claim social brokerage or strong continuity.

// centralNativeSession is the browser-safe bootstrap projection used by assertions.
type centralNativeSession struct {
	User struct {
		ID      int64   `json:"id"`      // retained local account identifier
		Balance float64 `json:"balance"` // local funds unaffected by authentication
	} `json:"user"` // existing product profile shape
	CSRFToken string    `json:"csrf_token"` // separate browser request binding
	ExpiresAt time.Time `json:"expires_at"` // fixed human authentication deadline
	AuthMode  string    `json:"auth_mode"`  // explicit opaque-cookie mode
}

// centralNativeOutput bounds child diagnostics while keeping the pipe writable.
type centralNativeOutput struct {
	data     []byte // retained prefix for an explicitly bounded native report
	exceeded bool   // whether any child output exceeded the report limit
}

// Write retains at most eight KiB while acknowledging every input byte to the
// child's output pipe. Returning the original length allows the process to
// finish even after the retained report limit is exceeded, instead of blocking
// cancellation on an unread stream. The exceeded flag prevents that truncated
// prefix from being accepted as a complete success report. Callers inspect
// only validated fields and never copy arbitrary retained diagnostics into
// test logs.
func (o *centralNativeOutput) Write(data []byte) (int, error) {
	remaining := max(0, 8192-len(o.data))
	o.data = append(o.data, data[:min(remaining, len(data))]...)
	o.exceeded = o.exceeded || len(data) > remaining
	return len(data), nil
}

// TestCentralNativeBFFCookieFlow runs a real callback, browser, local
// ownership and revocation chain. It requires
// integration,native_identity,embed after building the frontend and rejects
// absent native dependencies instead of skipping qualification.
func TestCentralNativeBFFCookieFlow(t *testing.T) {
	t.Log(`{"nativeGetTokStage":"setup"}`)
	require.True(t, web.HasEmbeddedFrontend(), "native browser qualification requires the embed build tag and real frontend dist")
	origin := centralNativeLoopbackURL(t, "GETTOK_NATIVE_ORIGIN")
	identityURL := centralNativeLoopbackURL(t, "GETTOK_NATIVE_IDENTITY_URL")
	issuer := centralNativeLoopbackURL(t, "IDENTITY_TEST_ISSUER")
	adminDSN := centralNativeRequired(t, "GETTOK_NATIVE_DATABASE_URL")
	t.Setenv("TOKENROUTER_TEST_POSTGRES_DSN", adminDSN)
	// The database fixture validates loopback and *_test before creating its own
	// randomly named database. It never migrates or drops the supplied admin DB.
	db := postgrescontainer.New(t)
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	repository := settingspostgres.NewSettingRepository(client)
	for key, value := range map[string]string{
		"registration_enabled": "true", "force_email_on_third_party_signup": "true",
		"email_verify_enabled": "false", "invitation_code_enabled": "false",
		"promo_code_enabled": "false", "login_agreement_enabled": "false",
		"turnstile_enabled": "false", "tencent_captcha_enabled": "false", "aliyun_captcha_enabled": "false",
		"backend_mode_enabled": "false", "site_name": "GetTok native qualification",
		"default_balance": "17", "default_concurrency": "2",
		"auth_source_default_oidc_balance": "17", "auth_source_default_oidc_concurrency": "2",
		"auth_source_default_oidc_grant_on_signup": "true",
	} {
		require.NoError(t, repository.Set(t.Context(), key, value))
	}
	cfg := &config.Config{Timezone: "UTC", CentralIdentity: authconfig.CentralIdentityConfig{
		Enabled: true, TestLoopback: true, Origin: origin.String(), APIURL: identityURL.String(), IssuerURL: issuer.String(),
		AuthorityIncarnation: "keycloak-test-v1", ConsumerID: "gettok", ProviderName: "Agent Teams TEST",
		ClientID: "gettok-test-bff", ClientSecret: centralNativeRequired(t, "IDENTITY_TEST_CLIENT_SECRET"),
		WorkloadClientID: "gettok-test-workload", WorkloadClientSecret: centralNativeRequired(t, "IDENTITY_TEST_WORKLOAD_SECRET"),
	}}
	cfg.Default.UserBalance, cfg.Default.UserConcurrency = 17, 2
	cfg.JWT.Secret, cfg.JWT.ExpireHour = strings.Repeat("native-only-", 4), 1
	cfg.Server.FrontendURL = origin.String()
	require.NoError(t, cfg.CentralIdentity.Validate())
	usersRepository := identitypostgres.NewUserStore(client, db)
	authSettings := newUserBindingSettings(repository, cfg)
	graph := provideIdentityAuthGraph(client, usersRepository, nil, nil, cfg, authSettings, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	users := newUserProfileCore(t, usersRepository)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	cipher, err := cryptoinfra.NewAESEncryptor(key)
	require.NoError(t, err)
	store := settings.New(repository)
	backend := provideBackendMode(store)
	central := provideCentralIdentity(cfg, db, graph, users, authSettings, backend, nil, cipher)
	public := provideSitePublic(store, provideOAuthSettings(store, cfg), cfg, timezone.NewCalendar(time.UTC))
	runtime := identityHTTPSettings{identityAuthSettings: authSettings, BackendMode: backend, public: public}
	publicHTTP := provideSitePublicHTTP(public, BuildInfo{Version: "native-identity-test"})
	frontend, err := web.NewFrontendServer(public)
	require.NoError(t, err)
	engine := gin.New()
	require.NoError(t, engine.SetTrustedProxies(nil))
	engine.Use(gin.Recovery(), middleware.Locale(func() string { return "en" }), middleware.SecurityHeaders(httpconfig.CSPConfig{Enabled: true}, nil), frontend.Middleware())
	v1 := engine.Group("/api/v1")
	// The native fixture selects disabled anonymous challenge/rate policy only;
	// every Identity, provider, ownership and cookie operation is the real adapter.
	pass := func(c *gin.Context) { c.Next() }
	guards := identityhttp.AuthRouteMiddleware{Audit: pass, BackendAuth: identityhttp.BackendModeAuthGuard(backend), Limit: func(string, int, time.Duration) gin.HandlerFunc { return pass }}
	identityhttp.RegisterCentralAuthenticationRoutes(v1, central, guards)
	v1.GET("/settings/public", publicHTTP.GetPublicSettings)
	sessions := identityhttp.NewSessionHandler(graph.Core, users, runtime, nil, nil, nil, identityhttp.SessionHTTPOptions{BackendMode: runtime.ReadBackendMode})
	legacy := identityhttp.JWTAuth(graph.Core, users, users, authSettings, nil)
	v1.GET("/auth/me", central.Wrap(legacy, false), identityhttp.BackendModeUserGuard(backend), sessions.GetCurrentUser)
	v1.POST("/auth/logout", central.Logout)
	listener, err := net.Listen("tcp", origin.Host)
	require.NoError(t, err)
	server := &http.Server{Handler: engine, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, server.Shutdown(ctx))
		require.ErrorIs(t, <-served, http.ErrServerClosed)
	})
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	httpClient := &http.Client{Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Log(`{"nativeGetTokStage":"bff-started"}`)
	centralNativeLogin(t, httpClient, origin, issuer, identity.CentralIntentLogin, "account_not_linked")
	t.Log(`{"nativeGetTokStage":"unbound-login-rejected"}`)
	centralNativeLogin(t, httpClient, origin, issuer, identity.CentralIntentRegister, "")
	t.Log(`{"nativeGetTokStage":"registration-completed"}`)
	response, body := centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/central/session", "", "", "")
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	var first centralNativeSession
	centralNativeDecode(t, body, &first)
	require.Equal(t, "central", first.AuthMode)
	require.Positive(t, first.User.ID)
	require.Equal(t, float64(17), first.User.Balance)
	require.Len(t, first.CSRFToken, 64)
	require.WithinDuration(t, time.Now(), first.ExpiresAt, identity.CentralAdmissionBudget)
	// A persisted grant forces both profile endpoints to hydrate related state;
	// comparing empty new-user profiles alone would miss a missing grant reader.
	group, err := client.Group.Create().SetName("native-central-profile").SetIsExclusive(true).Save(t.Context())
	require.NoError(t, err)
	_, err = client.UserAllowedGroup.Create().SetUserID(first.User.ID).SetGroupID(group.ID).Save(t.Context())
	require.NoError(t, err)
	response, body = centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/central/session", "", "", first.CSRFToken)
	require.Equal(t, http.StatusOK, response.StatusCode)
	var bootstrap struct {
		User map[string]any `json:"user"` // complete existing profile response projection
	}
	centralNativeDecode(t, body, &bootstrap)
	grants, ok := bootstrap.User["allowed_groups"].([]any)
	require.True(t, ok, "session bootstrap must retain hydrated local group grants")
	require.Equal(t, []any{float64(group.ID)}, grants)
	response, body = centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/me", "", "", first.CSRFToken)
	require.Equal(t, http.StatusOK, response.StatusCode)
	var profile map[string]any
	centralNativeDecode(t, body, &profile)
	bootstrapJSON, err := json.Marshal(bootstrap.User)
	require.NoError(t, err)
	profileJSON, err := json.Marshal(profile)
	require.NoError(t, err)
	require.True(t, bytes.Equal(bootstrapJSON, profileJSON), "central bootstrap and current-user profile must agree")
	response, _ = centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/me", "", "", "")
	require.Equal(t, http.StatusForbidden, response.StatusCode, "an old legacy tab must not adopt another tab's cookie implicitly")
	response, _ = centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/central/session", "", "", strings.Repeat("a", 64))
	require.Equal(t, http.StatusForbidden, response.StatusCode)
	response, _ = centralNativeRequest(t, httpClient, http.MethodPost, origin.String()+"/api/v1/auth/central/logout", "{}", origin.String(), "")
	require.Equal(t, http.StatusForbidden, response.StatusCode)
	response, _ = centralNativeRequest(t, httpClient, http.MethodPost, origin.String()+"/api/v1/auth/central/logout", "{}", "https://other.example.invalid", first.CSRFToken)
	require.Equal(t, http.StatusForbidden, response.StatusCode)
	response, _ = centralNativeRequest(t, httpClient, http.MethodPost, origin.String()+"/api/v1/auth/central/logout", "{}", origin.String(), first.CSRFToken)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Empty(t, response.Header.Values("Set-Cookie"), "a delayed logout must not erase a replacement session cookie")
	response, _ = centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/me", "", "", first.CSRFToken)
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	t.Log(`{"nativeGetTokStage":"logout-revocation-verified"}`)
	centralNativeLogin(t, httpClient, origin, issuer, identity.CentralIntentLogin, "")
	response, body = centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/central/session", "", "", "")
	require.Equal(t, http.StatusOK, response.StatusCode)
	var next centralNativeSession
	centralNativeDecode(t, body, &next)
	require.Equal(t, first.User.ID, next.User.ID)
	require.Equal(t, first.User.Balance, next.User.Balance)
	require.NotEqual(t, first.CSRFToken, next.CSRFToken)
	t.Log(`{"nativeGetTokStage":"owner-preserved"}`)
	t.Log(`{"nativeGetTokStage":"browser-start"}`)
	centralNativeCommand(t, "GETTOK_NATIVE_BROWSER_COMMAND")
	t.Log(`{"nativeGetTokStage":"browser-completed"}`)
	// The browser owns another session. Its logout must not revoke this client.
	response, _ = centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/me", "", "", next.CSRFToken)
	require.Equal(t, http.StatusOK, response.StatusCode)
	var accountID, incarnation string
	var revision uint64
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT account_id,authority_incarnation,(status_evidence->>'Revision')::bigint FROM central_identity_bindings WHERE local_user_id=$1", next.User.ID).Scan(&accountID, &incarnation, &revision))
	require.Positive(t, revision)
	centralNativeCommand(t, "GETTOK_NATIVE_LIFECYCLE_COMMAND", accountID, incarnation, "suspend", strconv.FormatUint(revision, 10))
	response, _ = centralNativeRequest(t, httpClient, http.MethodGet, origin.String()+"/api/v1/auth/me", "", "", next.CSRFToken)
	require.Equal(t, http.StatusUnauthorized, response.StatusCode, "fresh central suspension must invalidate the original BFF cookie")
	t.Log(`{"nativeGetTokStage":"central-revocation-verified"}`)
	var preservedBalance float64
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT balance FROM users WHERE id=$1 AND central_managed", first.User.ID).Scan(&preservedBalance))
	require.Equal(t, first.User.Balance, preservedBalance)
	t.Log("native GetTok BFF, browser, Keycloak, Identity HTTP, ownership preservation and suspension checks passed")
}

// centralNativeLogin follows the configured native issuer and exact BFF
// callback using the real cookie jar. The first flow can submit the synthetic
// Keycloak credentials, while later flows reuse its provider session. Every
// response is handled explicitly within a finite redirect budget, so an
// unexpected destination cannot receive those credentials. The final frontend
// callback must have the exact configured origin and path, no credentials or
// fragment, and either no query or one expected public error. Successful flows
// also require the real HttpOnly cookie without logging provider URLs or payloads.
func centralNativeLogin(t *testing.T, client *http.Client, origin, issuer *url.URL, intent, expectedError string) {
	t.Helper()
	response, body := centralNativeRequest(t, client, http.MethodPost, origin.String()+"/api/v1/auth/central/start", `{"intent":"`+intent+`"}`, origin.String(), "")
	require.Equal(t, http.StatusOK, response.StatusCode)
	var start struct {
		AuthorizationURL string `json:"authorization_url"` // trusted server-created provider destination
	}
	centralNativeDecode(t, body, &start)
	next, err := url.Parse(start.AuthorizationURL)
	require.True(t, err == nil, "native provider destination must be a valid URL; diagnostic URL is withheld")
	require.Equal(t, issuer.Scheme+"://"+issuer.Host, next.Scheme+"://"+next.Host)
	response, body = centralNativeRequest(t, client, http.MethodGet, next.String(), "", "", "")
	for range 8 {
		if response.StatusCode == http.StatusOK {
			form := regexp.MustCompile(`<form\b[^>]*\baction="([^"]+)"`).FindSubmatch(body)
			require.Len(t, form, 2, "native Keycloak credential form must be present")
			action, err := url.Parse(html.UnescapeString(string(form[1])))
			require.True(t, err == nil, "native credential form must have a valid action; diagnostic URL is withheld")
			require.Equal(t, issuer.Scheme+"://"+issuer.Host, action.Scheme+"://"+action.Host)
			payload := url.Values{"username": {"fixture-gettok"}, "password": {centralNativeRequired(t, "IDENTITY_TEST_USER_PASSWORD")}}.Encode()
			response, body = centralNativeRequest(t, client, http.MethodPost, action.String(), payload, issuer.Scheme+"://"+issuer.Host, "")
			continue
		}
		require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, response.StatusCode, "native provider must return a bounded redirect")
		destination, err := response.Location()
		require.True(t, err == nil, "native redirect must have a valid location; diagnostic URL is withheld")
		if destination.Host == origin.Host && destination.Path == "/auth/central/callback" {
			require.True(t, destination.Scheme == origin.Scheme && destination.User == nil && destination.Opaque == "" && destination.RawPath == "" && destination.Fragment == "" && destination.RawFragment == "", "frontend callback must have the exact origin and path without userinfo or a fragment")
			if expectedError == "" {
				require.True(t, destination.RawQuery == "" && !destination.ForceQuery, "successful frontend callback must not receive query data")
			} else {
				query, parseErr := url.ParseQuery(destination.RawQuery)
				errorValues := query["error"]
				require.True(t, parseErr == nil && len(query) == 1 && len(errorValues) == 1 && errorValues[0] == expectedError && !destination.ForceQuery, "failed frontend callback must contain exactly its expected public error")
			}
			if expectedError == "" {
				found := false
				for _, cookie := range response.Cookies() {
					if cookie.Name == "gettok-central-test" {
						found = true
						require.True(t, cookie.HttpOnly)
						require.False(t, cookie.Secure, "HTTP is allowed only by the explicit loopback TEST profile")
						require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
						require.Empty(t, cookie.Domain)
						require.Equal(t, "/", cookie.Path)
					}
				}
				require.True(t, found, "the real BFF callback must issue an HttpOnly TEST cookie")
			}
			return
		}
		require.True(t, destination.Scheme == issuer.Scheme && destination.Host == issuer.Host || destination.Scheme == origin.Scheme && destination.Host == origin.Host && destination.Path == "/api/v1/auth/central/callback", "native redirect may reach only configured issuer or exact BFF callback")
		response, body = centralNativeRequest(t, client, http.MethodGet, destination.String(), "", "", "")
	}
	t.Fatal("native authorization exceeded its finite redirect budget")
}

// centralNativeRequest performs one bounded real request using a client with
// automatic redirects disabled. It closes the response body and reports fixed
// failure messages so transport errors cannot disclose provider URLs, codes or
// cookies.
func centralNativeRequest(t *testing.T, client *http.Client, method, address, payload, origin, csrf string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, address, strings.NewReader(payload))
	require.True(t, err == nil, "native HTTP request could not be constructed; diagnostic URL is withheld")
	if payload != "" {
		contentType := "application/json"
		if strings.HasPrefix(payload, "password=") || strings.HasPrefix(payload, "username=") {
			contentType = "application/x-www-form-urlencoded"
		}
		request.Header.Set("Content-Type", contentType)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	require.True(t, err == nil, "native HTTP transport failed; diagnostic URL is withheld")
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	require.NoError(t, response.Body.Close())
	require.NoError(t, err)
	return response, body
}

// centralNativeDecode validates a successful browser envelope and decodes its
// data into the supplied target. Provider credential fields are rejected
// before parsing the projection, preserving the BFF's browser custody
// boundary.
func centralNativeDecode(t *testing.T, body []byte, target any) {
	t.Helper()
	for _, forbidden := range [][]byte{[]byte(`"access_token"`), []byte(`"refresh_token"`), []byte(`"id_token"`)} {
		require.False(t, bytes.Contains(body, forbidden), "browser JSON must not contain provider credentials")
	}
	var envelope struct {
		Code int             `json:"code"` // public numeric success status
		Data json.RawMessage `json:"data"` // browser-safe response projection
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	require.Zero(t, envelope.Code)
	require.NoError(t, json.Unmarshal(envelope.Data, target))
}

// centralNativeCommand executes an explicit native runner argv without shell
// interpretation and validates its bounded completion report. The surrounding
// process owns the environment and supplies only disposable TEST credentials.
// Cancellation first interrupts the child so the browser runner can close its
// Chromium process; the bounded wait then terminates an unresponsive child.
// Arbitrary stdout and stderr never reach test logs, because either may include
// callback URLs or credentials. Browser failures expose only a fixed phase name.
func centralNativeCommand(t *testing.T, name string, trailing ...string) {
	t.Helper()
	var argv []string
	require.NoError(t, json.Unmarshal([]byte(centralNativeRequired(t, name)), &argv))
	require.NotEmpty(t, argv)
	require.True(t, filepath.IsAbs(argv[0]), "native child executable must have an absolute path")
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, argv[0], append(argv[1:], trailing...)...)
	command.Env = os.Environ()
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	var output, diagnostic centralNativeOutput
	command.Stdout, command.Stderr = &output, &diagnostic
	err := command.Run()
	if err != nil {
		if name == "GETTOK_NATIVE_BROWSER_COMMAND" && !diagnostic.exceeded {
			var failure struct {
				Result string `json:"nativeGetTokBrowser"` // fixed failure result discriminator
				Phase  string `json:"phase"`               // runner-owned bounded failure location
			}
			if json.Unmarshal(bytes.TrimSpace(diagnostic.data), &failure) == nil && failure.Result == "failed" {
				// Reconstruct only known phases so a modified child cannot put provider
				// errors, callback queries, or credential text into the test output.
				switch failure.Phase {
				case "launch", "rendered-login", "provider-and-callback", "protected-profile-and-csrf", "reload-restoration", "confirmed-logout":
					t.Logf(`{"nativeGetTokBrowser":"failed","phase":%q}`, failure.Phase)
				}
			}
		}
		t.Fatalf("native %s failed: %v; child credential-bearing diagnostics are withheld", name, err)
	}
	require.False(t, output.exceeded || diagnostic.exceeded, "native child must emit only a bounded completion report")
	var report map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.data), &report))
	if name == "GETTOK_NATIVE_BROWSER_COMMAND" {
		require.Equal(t, "passed", report["nativeGetTokBrowser"])
		for _, property := range []string{"renderedLogin", "callbackWithoutCredentials", "cookieHttpOnly", "memoryOnlySession", "csrfRejected", "reloadPreservesDeadline", "logoutRevoked"} {
			require.Equal(t, true, report[property], "native browser must qualify "+property)
		}
		require.Equal(t, "not-admitted", report["independentContinuity"])
		// Log a reconstructed witness only; arbitrary child stdout is never copied.
		t.Log(`{"nativeGetTokBrowser":"passed"}`)
		return
	}
	require.Equal(t, true, report["committed"])
	require.Equal(t, trailing[2], report["action"])
	t.Log(`{"nativeGetTokLifecycle":"committed"}`)
}

// centralNativeRequired reads one explicit native runner setting and fails
// when it is absent. The diagnostic names the setting only, keeping its value
// outside test logs and preventing silently skipped qualification.
func centralNativeRequired(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	require.NotEmpty(t, value, "native qualification requires "+name)
	return value
}

// centralNativeLoopbackURL validates an explicit native HTTP authority with an
// IPv4 loopback host and port. User information, query overrides and fragments
// are rejected before the fixture uses that endpoint.
func centralNativeLoopbackURL(t *testing.T, name string) *url.URL {
	t.Helper()
	u, err := url.Parse(centralNativeRequired(t, name))
	require.NoError(t, err)
	require.Equal(t, "http", u.Scheme)
	require.Equal(t, "127.0.0.1", u.Hostname())
	require.NotEmpty(t, u.Port())
	require.Nil(t, u.User)
	require.Empty(t, u.RawQuery)
	require.Empty(t, u.Fragment)
	return u
}
