package provider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// central_identity_test.go checks authority failure categories through the
// generated Connect client and a real local HTTP server. An interrupted response
// must remain retryable, while rejected credentials keep their exact denial
// category. Separate deterministic concurrency tests hold the workload HTTP
// transport at its request boundary to check cancellation and shared refreshes.

// centralCredentialTransport supplies the controlled HTTP boundary for concurrent grants.
type centralCredentialTransport func(*http.Request) (*http.Response, error)

// centralCredentialResult retains a caller's independently observed workload grant outcome.
type centralCredentialResult struct {
	token string // credential returned to caller
	err   error  // stable caller failure category
}

// TestCentralAuthorityPreservesOutageCategory returns real Connect failure
// responses after a workload grant. An internal service failure or truncated
// successful response remains retryable, while explicit credential rejection stays denied.
func TestCentralAuthorityPreservesOutageCategory(t *testing.T) {
	for _, row := range []struct {
		name      string // isolated protocol response scenario
		status    int    // actual authority HTTP status
		code      string // Connect protocol failure category
		truncated bool   // successful response ends before its declared length
		want      error  // exact local failure sentinel
	}{
		{name: "server outage", status: http.StatusInternalServerError, code: "internal", want: identity.ErrCentralUnavailable},
		{name: "credential rejected", status: http.StatusUnauthorized, code: "unauthenticated", want: identity.ErrCentralEvidenceInvalid},
		{name: "interrupted response", status: http.StatusOK, truncated: true, want: identity.ErrCentralUnavailable},
	} {
		t.Run(row.name, func(t *testing.T) {
			var statusCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/token" {
					_, _ = w.Write([]byte(`{"access_token":"test-workload-credential","token_type":"Bearer","expires_in":60}`))
					return
				}
				if r.URL.Path != "/identity.v1.IdentityService/GetAccountStatus" {
					t.Error("generated client requested an unexpected authority operation")
					w.WriteHeader(http.StatusNotFound)
					return
				}
				statusCalls.Add(1)
				if row.truncated {
					// A short body after successful headers exercises Connect's actual
					// wrapped I/O error, independently of protocol credential rejection.
					w.Header().Set("Content-Type", "application/proto")
					w.Header().Set("Content-Length", "128")
					w.WriteHeader(row.status)
					_, _ = w.Write([]byte{0x0a})
					return
				}
				w.WriteHeader(row.status)
				_, _ = w.Write([]byte(`{"code":"` + row.code + `","message":"private-provider-diagnostic"}`))
			}))
			t.Cleanup(server.Close)
			client := NewCentralIdentityClient(CentralAuthorityOptions{BaseURL: server.URL, TokenURL: server.URL + "/token", WorkloadClientID: "test-workload", WorkloadClientSecret: "disposable-test-secret"})
			_, err := client.GetAccountStatus(t.Context(), identity.CentralAccountReference{AccountID: "test-owner", AuthorityIncarnation: "test-authority"})
			require.EqualValues(t, 1, statusCalls.Load(), "workload failure must not substitute for an RPC mapper assertion")
			require.ErrorIs(t, err, row.want)
			require.NotContains(t, err.Error(), "private-provider-diagnostic")
		})
	}
}

// TestCentralAuthorityKeepsExplicitCredentialDenial supplies I/O-shaped causes
// beneath explicit protocol denials. Those denials and unknown non-transport
// evidence must retain their authentication failure category.
func TestCentralAuthorityKeepsExplicitCredentialDenial(t *testing.T) {
	for _, failure := range []error{
		connect.NewError(connect.CodeUnauthenticated, io.ErrUnexpectedEOF),
		connect.NewError(connect.CodePermissionDenied, io.ErrUnexpectedEOF),
		connect.NewError(connect.CodeUnknown, errors.New("unrecognized provider evidence")),
	} {
		require.ErrorIs(t, centralRPCError(failure), identity.ErrCentralEvidenceInvalid)
	}
}

// TestCentralWorkloadRefreshSharesCancellableWait verifies cancellation while
// one HTTP grant remains pending. Cancelling either the initiating caller or a
// follower must leave other callers sharing one success or one failure.
func TestCentralWorkloadRefreshSharesCancellableWait(t *testing.T) {
	for _, row := range []struct {
		name        string // isolated shared refresh outcome
		status      int    // token endpoint HTTP result
		cancelIndex int    // initiating or following caller cancelled
		want        error  // common remaining caller outcome
	}{
		{"success after follower cancellation", http.StatusOK, 1, nil},
		{"failure after initiator cancellation", http.StatusServiceUnavailable, 0, identity.ErrCentralUnavailable},
	} {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := NewCentralIdentityClient(CentralAuthorityOptions{BaseURL: "https://identity.example.test", TokenURL: "https://identity.example.test/token"})
				release := make(chan struct{})
				releaseGrant := sync.OnceFunc(func() { close(release) })
				t.Cleanup(releaseGrant)
				started := make(chan context.Context, 1)
				var requests atomic.Int32
				client.http.Transport = centralCredentialTransport(func(r *http.Request) (*http.Response, error) {
					if requests.Add(1) == 1 {
						started <- r.Context()
					}
					select {
					case <-r.Context().Done():
						return nil, r.Context().Err()
					case <-release:
						return &http.Response{StatusCode: row.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"shared-workload-token","token_type":"Bearer","expires_in":60}`))}, nil
					}
				})
				alreadyCancelled, cancelAlready := context.WithCancel(t.Context())
				cancelAlready()
				token, err := client.workloadCredential(alreadyCancelled)
				require.ErrorIs(t, err, identity.ErrCentralUnavailable)
				require.Empty(t, token)
				require.Zero(t, requests.Load(), "an already cancelled caller must not start a refresh")
				cancelledContext, cancel := context.WithCancel(t.Context())
				defer cancel()
				var results [3]chan centralCredentialResult
				for i := range results {
					results[i] = make(chan centralCredentialResult, 1)
					ctx := t.Context()
					if i == row.cancelIndex {
						ctx = cancelledContext
					}
					go func() {
						token, err := client.workloadCredential(ctx)
						results[i] <- centralCredentialResult{token: token, err: err}
					}()
					// The first caller enters the grant before followers join. Waiting
					// uses durable channel barriers rather than elapsed scheduling guesses.
					synctest.Wait()
				}
				grantContext := <-started
				require.EqualValues(t, 1, requests.Load())
				cancel()
				synctest.Wait()
				select {
				case result := <-results[row.cancelIndex]:
					require.ErrorIs(t, result.err, identity.ErrCentralUnavailable)
					require.Empty(t, result.token)
				default:
					t.Fatal("cancelled caller remained blocked behind the workload refresh")
				}
				require.NoError(t, grantContext.Err(), "one caller must not cancel the shared grant")
				for i := range results {
					if i != row.cancelIndex {
						require.Empty(t, results[i], "live callers must still await the same pending grant")
					}
				}
				releaseGrant()
				synctest.Wait()
				for i := range results {
					if i == row.cancelIndex {
						continue
					}
					result := <-results[i]
					if row.want != nil {
						require.ErrorIs(t, result.err, row.want)
						require.Empty(t, result.token)
					} else {
						require.NoError(t, result.err)
						require.Equal(t, "shared-workload-token", result.token)
					}
				}
				require.EqualValues(t, 1, requests.Load(), "concurrent failures must not start serial grants")
				if row.want == nil {
					token, err := client.workloadCredential(t.Context())
					require.NoError(t, err)
					require.Equal(t, "shared-workload-token", token)
					require.EqualValues(t, 1, requests.Load(), "a valid cache hit must not make another grant")
					token, err = client.workloadCredential(alreadyCancelled)
					require.ErrorIs(t, err, identity.ErrCentralUnavailable)
					require.Empty(t, token)
					require.EqualValues(t, 1, requests.Load(), "cancellation must also precede a warm cache hit")
				}
			})
		})
	}
}

// TestCentralWorkloadRefreshHasIndependentDeadline holds the token endpoint
// until its request context expires. A caller without its own deadline must
// still receive unavailable after the shared five-second refresh budget.
func TestCentralWorkloadRefreshHasIndependentDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := NewCentralIdentityClient(CentralAuthorityOptions{BaseURL: "https://identity.example.test", TokenURL: "https://identity.example.test/token"})
		client.http.Transport = centralCredentialTransport(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		started := time.Now()
		token, err := client.workloadCredential(t.Context())
		require.ErrorIs(t, err, identity.ErrCentralUnavailable)
		require.Empty(t, token)
		require.Equal(t, 5*time.Second, time.Since(started))
	})
}

// RoundTrip delegates one HTTP grant to the controlled concurrency fixture.
func (f centralCredentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
