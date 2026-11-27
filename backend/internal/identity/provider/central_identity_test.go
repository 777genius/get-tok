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
	"github.com/agent-teams-ai/identity/packages/contracts/gen/go/identity/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// central_identity_test.go checks authority failure categories through the
// generated Connect client and a real local HTTP server. An interrupted response
// must remain retryable, while human and account denials keep their categories.
// Workload rejection is retried once without discarding a concurrently renewed
// grant. Separate deterministic concurrency tests hold the workload HTTP
// transport at its request boundary to check cancellation and shared refreshes.

// centralCredentialTransport supplies the controlled HTTP boundary for concurrent grants.
type centralCredentialTransport func(*http.Request) (*http.Response, error)

// centralCredentialResult retains a caller's independently observed workload grant outcome.
type centralCredentialResult struct {
	token string // credential returned to caller
	err   error  // stable caller failure category
}

// TestCentralAuthorityPreservesOutageCategory returns real Connect failure
// responses after a workload grant, or directly for a human login. Service and
// workload failures remain retryable; human and account refusals stay denied.
func TestCentralAuthorityPreservesOutageCategory(t *testing.T) {
	for _, row := range []struct {
		name      string // isolated protocol response scenario
		status    int    // actual authority HTTP status
		code      string // Connect protocol failure category
		truncated bool   // successful response ends before its declared length
		human     bool   // uses the human operation without a workload grant
		calls     int32  // bounded number of actual authority RPC attempts
		want      error  // exact local failure sentinel
	}{
		{name: "server outage", status: http.StatusInternalServerError, code: "internal", calls: 1, want: identity.ErrCentralUnavailable},
		{name: "workload credential rejected twice", status: http.StatusUnauthorized, code: "unauthenticated", calls: 2, want: identity.ErrCentralUnavailable},
		{name: "account access denied", status: http.StatusForbidden, code: "permission_denied", calls: 1, want: identity.ErrCentralEvidenceInvalid},
		{name: "human credential rejected", status: http.StatusUnauthorized, code: "unauthenticated", human: true, calls: 1, want: identity.ErrCentralEvidenceInvalid},
		{name: "interrupted response", status: http.StatusOK, truncated: true, calls: 1, want: identity.ErrCentralUnavailable},
	} {
		t.Run(row.name, func(t *testing.T) {
			var statusCalls, grantCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/token" {
					grantCalls.Add(1)
					_, _ = w.Write([]byte(`{"access_token":"test-workload-credential","token_type":"Bearer","expires_in":60}`))
					return
				}
				procedure := "/identity.v1.IdentityService/GetAccountStatus"
				if row.human {
					procedure = "/identity.v1.IdentityService/ResolveSelf"
				}
				if r.URL.Path != procedure {
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
			var err error
			if row.human {
				_, err = client.ResolveSelf(t.Context(), "test-human", "test-command")
				require.Zero(t, grantCalls.Load(), "human rejection must not acquire a workload grant")
			} else {
				_, err = client.GetAccountStatus(t.Context(), identity.CentralAccountReference{AccountID: "test-owner", AuthorityIncarnation: "test-authority"})
				require.Equal(t, row.calls, grantCalls.Load(), "rejected grants must be acquired again at most once")
			}
			require.Equal(t, row.calls, statusCalls.Load(), "a grant failure must not substitute for the actual RPC assertion")
			require.ErrorIs(t, err, row.want)
			require.NotContains(t, err.Error(), "private-provider-diagnostic")
			if row.calls == 2 {
				require.Empty(t, client.cachedWorkloadCredential(), "the twice-rejected grant must not remain cached")
			}
		})
	}
}

// TestCentralWorkloadRejectionPreservesNewGrant holds a second response for the
// same rejected token until the first caller has refreshed and completed a real
// successful status RPC. The delayed rejection must reuse the newer cache entry
// rather than evicting it and starting a third grant.
func TestCentralWorkloadRejectionPreservesNewGrant(t *testing.T) {
	account := identity.CentralAccountReference{AccountID: "test-owner", AuthorityIncarnation: "test-authority"}
	firstOld, secondOld, releaseSecond := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseSecond) })
	var grants, oldCalls, freshCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		credential := "revoked-workload"
		if grants.Add(1) > 1 {
			credential = "renewed-workload"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + credential + `","token_type":"Bearer","expires_in":60}`))
	})
	const procedure = "/identity.v1.IdentityService/GetAccountStatus"
	mux.Handle(procedure, connect.NewUnaryHandler(procedure, func(ctx context.Context, request *connect.Request[identityv1.GetAccountStatusRequest]) (*connect.Response[identityv1.GetAccountStatusResponse], error) {
		switch request.Header().Get("Authorization") {
		case "Bearer revoked-workload":
			var barrier <-chan struct{}
			if oldCalls.Add(1) == 1 {
				close(firstOld)
				barrier = secondOld
			} else {
				close(secondOld)
				barrier = releaseSecond
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-barrier:
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("workload grant rejected"))
			}
		case "Bearer renewed-workload":
			freshCalls.Add(1)
			now := time.Now().UTC()
			return connect.NewResponse(&identityv1.GetAccountStatusResponse{Status: &identityv1.AccountStatusEvidence{
				Account: request.Msg.Account, ConsumerId: "gettok", Eligibility: identityv1.AccountEligibility_ACCOUNT_ELIGIBILITY_ACTIVE,
				AccountRevision: 1, SecurityEpoch: 1, AttachmentGeneration: 1,
				ObservedAt: timestamppb.New(now), ValidUntil: timestamppb.New(now.Add(time.Minute)),
			}}), nil
		default:
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("unexpected credential"))
		}
	}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	t.Cleanup(release)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	client := NewCentralIdentityClient(CentralAuthorityOptions{BaseURL: server.URL, TokenURL: server.URL + "/token"})
	_, err := client.workloadCredential(ctx)
	require.NoError(t, err)
	first, second := make(chan error, 1), make(chan error, 1)
	readStatus := func(result chan<- error) {
		status, err := client.GetAccountStatus(ctx, account)
		if err == nil && (status.Account != account || status.Eligibility != identity.CentralEligibilityActive) {
			err = errors.New("refreshed status did not preserve the exact active account")
		}
		result <- err
	}
	go readStatus(first)
	select {
	case <-firstOld:
	case <-ctx.Done():
		t.Fatal("initial status request did not reach the real authority")
	}
	go readStatus(second)
	require.NoError(t, <-first)
	require.Equal(t, "renewed-workload", client.cachedWorkloadCredential())
	release()
	require.NoError(t, <-second)
	require.EqualValues(t, 2, oldCalls.Load())
	require.EqualValues(t, 2, freshCalls.Load())
	require.EqualValues(t, 2, grants.Load(), "a delayed old rejection must not evict the new grant")
}

// TestCentralWorkloadPreservesTypedDenials sends real Connect details through
// the generated client. A lifecycle or unknown typed refusal must remain denied
// without renewing credentials, even under an unexpected authentication code.
func TestCentralWorkloadPreservesTypedDenials(t *testing.T) {
	for _, row := range []struct {
		name   string                         // explicit account decision variant
		code   connect.Code                   // actual protocol error category
		reason identityv1.IdentityErrorReason // typed account reason from the authority
		want   error                          // exact retained local denial
	}{
		{"suspended", connect.CodeFailedPrecondition, identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_ACCOUNT_SUSPENDED, identity.ErrCentralAccountInactive},
		{"closed under auth code", connect.CodeUnauthenticated, identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_ACCOUNT_CLOSED, identity.ErrCentralAccountInactive},
		{"unknown typed auth refusal", connect.CodeUnauthenticated, identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_UNSPECIFIED, identity.ErrCentralEvidenceInvalid},
	} {
		t.Run(row.name, func(t *testing.T) {
			detail, err := connect.NewErrorDetail(&identityv1.IdentityErrorDetail{Reason: row.reason})
			require.NoError(t, err)
			var grants, calls atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				grants.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"accepted-workload","token_type":"Bearer","expires_in":60}`))
			})
			const procedure = "/identity.v1.IdentityService/GetAccountStatus"
			mux.Handle(procedure, connect.NewUnaryHandler(procedure, func(context.Context, *connect.Request[identityv1.GetAccountStatusRequest]) (*connect.Response[identityv1.GetAccountStatusResponse], error) {
				calls.Add(1)
				failure := connect.NewError(row.code, errors.New("private-account-diagnostic"))
				failure.AddDetail(detail)
				return nil, failure
			}))
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)
			client := NewCentralIdentityClient(CentralAuthorityOptions{BaseURL: server.URL, TokenURL: server.URL + "/token"})
			_, err = client.GetAccountStatus(t.Context(), identity.CentralAccountReference{AccountID: "test-owner", AuthorityIncarnation: "test-authority"})
			require.ErrorIs(t, err, row.want)
			require.NotContains(t, err.Error(), "private-account-diagnostic")
			require.EqualValues(t, 1, calls.Load())
			require.EqualValues(t, 1, grants.Load())
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
