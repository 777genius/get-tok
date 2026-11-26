package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// central_identity_test.go checks the authority adapter's public failure
// categories through its generated Connect client and a real local HTTP server.
// An unavailable authority must not masquerade as expired human authentication,
// because the browser handles those outcomes differently. Upstream diagnostics
// remain outside the product's stable errors in either case.

// TestCentralAuthorityPreservesOutageCategory returns real Connect failure
// responses after a workload grant. An internal service failure remains
// retryable, while rejected authentication stays denied without diagnostic text.
func TestCentralAuthorityPreservesOutageCategory(t *testing.T) {
	for _, row := range []struct {
		name        string // isolated protocol response scenario
		status      int    // actual authority HTTP status
		code        string // Connect protocol failure category
		unavailable bool   // retain the authenticated browser during retryable failure
	}{
		{name: "server outage", status: http.StatusInternalServerError, code: "internal", unavailable: true},
		{name: "credential rejected", status: http.StatusUnauthorized, code: "unauthenticated"},
	} {
		t.Run(row.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/token" {
					_, _ = w.Write([]byte(`{"access_token":"test-workload-credential","token_type":"Bearer","expires_in":60}`))
					return
				}
				if r.URL.Path != "/identity.v1.IdentityService/GetAccountStatus" {
					t.Error("generated client requested an unexpected authority operation")
				}
				w.WriteHeader(row.status)
				_, _ = w.Write([]byte(`{"code":"` + row.code + `","message":"private-provider-diagnostic"}`))
			}))
			t.Cleanup(server.Close)
			client := NewCentralIdentityClient(CentralAuthorityOptions{BaseURL: server.URL, TokenURL: server.URL + "/token", WorkloadClientID: "test-workload", WorkloadClientSecret: "disposable-test-secret"})
			_, err := client.GetAccountStatus(context.Background(), identity.CentralAccountReference{AccountID: "test-owner", AuthorityIncarnation: "test-authority"})
			require.Error(t, err)
			require.Equal(t, row.unavailable, errors.Is(err, identity.ErrCentralUnavailable))
			require.False(t, strings.Contains(err.Error(), "private-provider-diagnostic"))
		})
	}
}
