package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/infra/telemetry/logging"
	"github.com/TokenFlux/TokenRouter/internal/pkg/apperror"
	response "github.com/TokenFlux/TokenRouter/internal/server/httpx"
)

// recovery_test.go checks public responses and authentication-safe panic
// diagnostics through the real middleware order and application log sink.
// Request and panic canaries must stay out of both Gin's diagnostic writer and
// retained structured events, while response commitment and broken-connection
// behavior remain distinct.

// TestRecoveryAuthenticationSecretsStayOutOfDiagnostics exercises ordinary and
// broken-connection panics in release and debug modes. Both diagnostic
// destinations and Gin's retained errors remain free of request or panic data.
func TestRecoveryAuthenticationSecretsStayOutOfDiagnostics(t *testing.T) {
	const canary = "recovery-private-canary"
	broken := &net.OpError{Op: "write", Net: "tcp", Err: &os.SyscallError{Syscall: "write", Err: errors.New("broken pipe " + canary)}}
	for _, mode := range []string{gin.ReleaseMode, gin.DebugMode} {
		t.Run(mode, func(t *testing.T) {
			originalMode := gin.Mode()
			gin.SetMode(mode)
			t.Cleanup(func() { gin.SetMode(originalMode) })
			for _, row := range []struct {
				name      string // panic classification used for this request
				recovered any    // secret-bearing value raised by the handler
				broken    bool   // whether another response write must be avoided
			}{
				{"string", canary, false},
				{"error", errors.New(canary), false},
				{"broken", broken, true},
				{"wrapped_broken", fmt.Errorf("%s: %w", canary, broken), true},
			} {
				t.Run(row.name, func(t *testing.T) {
					sink := initMiddlewareTestLogger(t)
					diagnosticPath := filepath.Join(t.TempDir(), "recovery.jsonl")
					options := logging.InitOptions{
						Level:           "debug",
						Format:          "json",
						ServiceName:     "tokenrouter",
						Environment:     "test",
						StacktraceLevel: "error",
						Output:          logging.OutputOptions{ToFile: true, FilePath: diagnosticPath},
					}
					require.NoError(t, logging.Init(options))
					t.Cleanup(func() {
						logging.Sync()
						options.Output = logging.OutputOptions{ToStdout: true}
						require.NoError(t, logging.Init(options))
						require.NoError(t, logging.CloseFiles())
					})
					var ginOutput bytes.Buffer
					originalWriter := gin.DefaultErrorWriter
					gin.DefaultErrorWriter = &ginOutput
					t.Cleanup(func() { gin.DefaultErrorWriter = originalWriter })
					var observed *gin.Context
					var recoveryReturned, writtenAfterRecovery bool
					router := gin.New()
					router.Use(func(c *gin.Context) {
						// Gin finalizes unwritten headers after the handler chain returns.
						// Observe recovery before that engine-owned write, while preserving
						// the production order of the three middleware under test.
						c.Next()
						recoveryReturned = true
						writtenAfterRecovery = c.Writer.Written()
					}, Recovery(), RequestLogger(), Logger())
					router.GET("/api/v1/auth/central/callback", func(c *gin.Context) {
						observed = c
						panic(row.recovered)
					})
					request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/central/callback?code="+canary+"-code&state="+canary+"-state", strings.NewReader(canary+"-body"))
					request.Header.Set("Authorization", "Bearer "+canary+"-bearer")
					request.Header.Set("Cookie", "__Host-gettok-central="+canary+"-session; __Host-gettok-central-login="+canary+"-transaction")
					request.Header.Set("X-CSRF-Token", canary+"-csrf")
					request.Header.Set("X-Request-ID", canary+"-caller")
					recorder := httptest.NewRecorder()
					router.ServeHTTP(recorder, request)
					require.True(t, recoveryReturned)
					require.True(t, observed.IsAborted())
					if row.broken {
						require.False(t, writtenAfterRecovery)
						require.Empty(t, recorder.Body.String())
						require.Len(t, observed.Errors, 1)
						require.EqualError(t, observed.Errors[0].Err, "response connection closed")
					} else {
						require.True(t, writtenAfterRecovery)
						require.Equal(t, http.StatusInternalServerError, recorder.Code)
						require.Empty(t, observed.Errors)
					}
					events := sink.list()
					require.Len(t, events, 1)
					require.Equal(t, "handler panic recovered", events[0].Message)
					require.Equal(t, "http.recovery", events[0].Fields["component"])
					require.Equal(t, recorder.Header().Get(requestIDHeader), events[0].Fields["request_id"])
					require.Len(t, recorder.Header().Get(requestIDHeader), 36)
					require.Equal(t, http.MethodGet, events[0].Fields["method"])
					require.Equal(t, "/api/v1/auth/central/callback", events[0].Fields["route"])
					require.Equal(t, row.broken, events[0].Fields["broken_connection"])
					stack, ok := events[0].Fields["stack"].(string)
					require.True(t, ok)
					require.Contains(t, stack, "recovery_test.go")
					require.LessOrEqual(t, strings.Count(stack, "\n"), 32)
					logging.Sync()
					diagnostics, err := os.ReadFile(diagnosticPath)
					require.NoError(t, err)
					var written map[string]any
					require.NoError(t, json.Unmarshal(bytes.TrimSpace(diagnostics), &written))
					require.Equal(t, events[0].Message, written["msg"])
					require.Equal(t, events[0].Fields["request_id"], written["request_id"])
					require.Equal(t, events[0].Fields["route"], written["route"])
					require.Equal(t, stack, written["stack"])
					require.NotContains(t, written, "stacktrace")
					encoded, err := json.Marshal(events)
					require.NoError(t, err)
					require.NotContains(t, ginOutput.String()+string(diagnostics)+string(encoded)+observed.Errors.String()+recorder.Body.String(), canary)
					require.Empty(t, ginOutput.String())
				})
			}
		})
	}
}

// TestRecovery compares an unwritten panic, successful handling, and a panic
// after a committed JSON response. Recovery supplies the public 500 envelope
// for the first case and keeps the already sent success response intact.
func TestRecovery(t *testing.T) {
	tests := []struct {
		name         string            // recovery scenario label
		handler      gin.HandlerFunc   // downstream panic or response action
		wantHTTPCode int               // expected final HTTP status
		wantBody     response.Response // expected decoded public envelope
	}{
		{
			name: "panic_returns_standard_json_500",
			handler: func(c *gin.Context) {
				panic("boom")
			},
			wantHTTPCode: http.StatusInternalServerError,
			wantBody: response.Response{
				Code:    http.StatusInternalServerError,
				Message: apperror.UnknownMessage,
				Reason:  "HTTP_500",
			},
		},
		{
			name: "no_panic_passthrough",
			handler: func(c *gin.Context) {
				response.Success(c, gin.H{"ok": true})
			},
			wantHTTPCode: http.StatusOK,
			wantBody: response.Response{
				Code:    0,
				Message: "success",
				Data:    map[string]any{"ok": true},
			},
		},
		{
			name: "panic_after_write_does_not_override_body",
			handler: func(c *gin.Context) {
				response.Success(c, gin.H{"ok": true})
				panic("boom")
			},
			wantHTTPCode: http.StatusOK,
			wantBody: response.Response{
				Code:    0,
				Message: "success",
				Data:    map[string]any{"ok": true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(Recovery())
			r.GET("/t", tt.handler)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/t", nil)
			r.ServeHTTP(w, req)

			require.Equal(t, tt.wantHTTPCode, w.Code)

			var got response.Response
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			require.Equal(t, tt.wantBody, got)
		})
	}
}
