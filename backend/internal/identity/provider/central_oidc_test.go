package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// central_oidc_test.go exercises provider response boundaries through the
// bounded central transport. Token types follow OAuth's case-insensitive rule,
// while UserInfo identity retains the literal sub needed for comparison with
// the signed ID token before profile hints can influence registration.

// TestCentralOIDCExchangeCodeTokenType varies only the provider's token scheme.
// Every valid Bearer letter case must retain the credentials, while another
// scheme is rejected and optional refresh credentials are discarded.
func TestCentralOIDCExchangeCodeTokenType(t *testing.T) {
	for _, tokenType := range []string{"Bearer", "bearer", "BEARER", "bEaReR", "MAC"} {
		t.Run(tokenType, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(identity.OIDCTokenResponse{TokenType: tokenType, AccessToken: "fixture-access", IDToken: "fixture-id", RefreshToken: "fixture-refresh"}); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)

			token, err := NewCentralOIDCClient().ExchangeCode(t.Context(), OIDCOptions{TokenURL: server.URL, ClientID: "fixture-client", ClientSecret: "fixture-secret"}, "fixture-code", "https://app.example.test/callback", "fixture-verifier")
			if tokenType == "MAC" {
				require.ErrorIs(t, err, identity.ErrCentralEvidenceInvalid)
				require.Nil(t, token)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tokenType, token.TokenType)
			require.Equal(t, "fixture-access", token.AccessToken)
			require.Equal(t, "fixture-id", token.IDToken)
			require.Empty(t, token.RefreshToken)
		})
	}
}

// TestCentralOIDCUserInfoSubject preserves the literal sub before the core
// compares it with signed claims. Legacy ID fallbacks, nonstring subjects and
// case-insensitive field aliases cannot become central identity evidence.
func TestCentralOIDCUserInfoSubject(t *testing.T) {
	for _, row := range []struct {
		name    string // provider response case name
		body    string // untrusted UserInfo JSON response
		subject string // exact accepted subject, empty when rejected
	}{
		{"standard", `{"sub":"subject","email":"person@example.test","email_verified":true}`, "subject"},
		{"configured ID does not override sub", `{"sub":"subject","id":"alternate"}`, "subject"},
		{"preserve whitespace", `{"sub":" subject "}`, " subject "},
		{"missing sub", `{"id":"subject"}`, ""},
		{"wrong field case", `{"Sub":"subject"}`, ""},
		{"empty sub", `{"sub":""}`, ""},
		{"null sub", `{"sub":null}`, ""},
		{"numeric sub", `{"sub":42}`, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(row.body)); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)

			claims, err := NewCentralOIDCClient().FetchUserInfo(t.Context(), OIDCOptions{UserInfoURL: server.URL, UserInfoIDPath: "id"}, &identity.OIDCTokenResponse{AccessToken: "fixture-access"})
			if row.subject == "" {
				require.ErrorIs(t, err, identity.ErrCentralEvidenceInvalid)
				require.Nil(t, claims)
				return
			}
			require.NoError(t, err)
			require.Equal(t, row.subject, claims.Subject)
			if row.name == "standard" {
				require.Equal(t, "person@example.test", claims.Email)
				require.NotNil(t, claims.EmailVerified)
				require.True(t, *claims.EmailVerified)
			}
		})
	}
}
