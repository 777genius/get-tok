package middleware

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/TokenFlux/TokenRouter/internal/infra/telemetry"
	"github.com/TokenFlux/TokenRouter/internal/infra/telemetry/logging"
	"github.com/TokenFlux/TokenRouter/internal/pkg/apperror"
	response "github.com/TokenFlux/TokenRouter/internal/server/httpx"
)

// recovery.go converts recoverable handler panics into an HTTP error response.
// A panic can occur before a response is committed or after a handler has
// already written it. The local recovery boundary emits the public 500
// envelope only for an unwritten response; broken connections and committed
// responses end the handler chain without another body.
//
// Diagnostics use the existing structured logger with server-owned request
// correlation, route templates and bounded stack frames. Neither request data
// nor the recovered value reaches a logger or Gin's error list. Avoiding Gin's
// built-in recovery also removes its independent broken-pipe request dump and
// raw-error branch, which otherwise bypass the configured response callback.

// Recovery catches downstream panics and retains the project's public JSON
// envelope for unwritten responses. Broken connections abort without another
// write, while an already committed response keeps its existing body. Logging
// receives fixed diagnostics and frame metadata instead of recovered values or
// request dumps. Gin's error list receives only a fixed broken-connection error,
// so later observers cannot disclose the original error through that second path.
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			recoveredErr, _ := recovered.(error)
			broken := isBrokenPipe(recoveredErr)
			logRecoveredPanic(c, broken)

			// A disconnected response cannot receive an error envelope. Retain a
			// safe classification for other observers without retaining its raw cause.
			if broken {
				_ = c.Error(errors.New("response connection closed"))
				c.Abort()
				return
			}

			// Gin marks committed headers and hijacks as written. Another envelope
			// would corrupt the response or attempt a write on an upgraded connection.
			if c.Writer.Written() {
				c.Abort()
				return
			}

			response.ErrorWithDetails(
				c,
				http.StatusInternalServerError,
				apperror.UnknownMessage,
				apperror.UnknownReason,
				nil,
			)
			c.Abort()
		}()
		c.Next()
	}
}

// logRecoveredPanic writes a fixed event through the application's structured
// logger. It selects only internal request correlation and a matched route's
// method and template; inherited caller aliases, raw URLs, request headers and
// recovered values are deliberately unavailable to this diagnostic function.
func logRecoveredPanic(c *gin.Context, broken bool) {
	requestID, method, route := "", "", c.FullPath()
	if c.Request != nil {
		requestID = telemetry.RequestIDValue(c.Request.Context())
		if route != "" {
			method = c.Request.Method
		}
	}
	// Use the bounded frame field instead of Zap's independent automatic stack.
	logging.With(
		zap.String("component", "http.recovery"),
		zap.String("request_id", requestID),
		zap.String("method", method),
		zap.String("route", route),
	).WithOptions(zap.AddStacktrace(logging.LevelFatal)).Error("handler panic recovered", zap.Bool("broken_connection", broken), zap.String("stack", recoveryFrames()))
}

// recoveryFrames captures at most thirty-two function, file and line tuples.
// It never reads source snippets or formats function arguments, either of
// which can contain credentials even when the panic value itself is omitted.
func recoveryFrames() string {
	var pcs [32]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	var trace strings.Builder
	for range len(pcs) {
		frame, more := frames.Next()
		// Builder writes cannot fail; frame metadata contains no request values.
		_, _ = fmt.Fprintf(&trace, "%s %s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}
	return trace.String()
}

// isBrokenPipe reports a broken pipe or peer reset wrapped in net.OpError and
// os.SyscallError. It follows errors.As chains and checks case-insensitive
// syscall text; nil or unmatched error structures return false.
func isBrokenPipe(err error) bool {
	if err == nil {
		return false
	}

	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}

	var syscallErr *os.SyscallError
	if !errors.As(opErr.Err, &syscallErr) {
		return false
	}

	msg := strings.ToLower(syscallErr.Error())
	return strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset by peer")
}
