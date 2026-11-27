package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// central_login_test.go checks callback decisions before local session persistence.
// Provider and storage probes supply explicit verified facts, while the production
// Finish method chooses the local deadline and decides whether registration needs
// creation artifacts. Real PostgreSQL tests separately verify atomic ownership and
// the equality of persisted timestamp and JSON representations.

// centralLoginProbe retains the observations used by one callback completion test.
type centralLoginProbe struct {
	CentralSessionStore                              // unused storage operations remain unavailable
	OIDCOAuthClient                                  // unused provider operations remain unavailable
	CentralIdentityAuthority                         // unused authority operations remain unavailable
	SecretEncryptor                                  // unused encryption operation remains unavailable
	transaction              CentralLoginTransaction // prepared browser transaction facts
	claims                   OIDCVerifiedClaims      // independently supplied signed claims
	resolution               CentralResolution       // independently supplied authority observations
	bound                    bool                    // exact binding preflight result
	bindingErr               error                   // preflight persistence failure category
	commitErr                error                   // final authoritative commit rejection
	checkedBinding           bool                    // whether callback checked ownership
	completion               *CentralLoginCompletion // attempted immutable persistence input
}

// centralRegistrationSettings requires invitations for every new account in these tests.
type centralRegistrationSettings struct {
	AuthSettings // unrelated policy reads remain unavailable
}

// TestCentralFinishFloorsOnlyLocalExpiry supplies sub-microsecond authority and
// token bounds. The chosen local expiry must round down while raw admission
// remains unchanged, including rejection when flooring exhausts the usable window.
func TestCentralFinishFloorsOnlyLocalExpiry(t *testing.T) {
	for _, row := range []struct {
		name      string        // isolated deadline selection scenario
		admission time.Duration // original authority deadline offset
		token     time.Duration // original signed token deadline offset
		want      time.Duration // expected persisted local deadline
		err       error         // expected admission failure category
	}{
		{"authority minimum", 4*time.Minute + 999*time.Nanosecond, 10 * time.Minute, 4 * time.Minute, nil},
		{"token minimum", 4*time.Minute + 999*time.Nanosecond, 2*time.Minute + 567*time.Nanosecond, 2 * time.Minute, nil},
		{"local minimum", 6*time.Minute + 999*time.Nanosecond, 10 * time.Minute, CentralAdmissionBudget, nil},
		{"floor exhausts clock margin", CentralClockUncertainty + 999*time.Nanosecond, 10 * time.Minute, 0, ErrCentralSessionExpired},
	} {
		t.Run(row.name, func(t *testing.T) {
			flow, probe, state, browser, now := centralLoginFixture(t, CentralIntentLogin)
			probe.resolution.Admission.ValidUntil = now.Add(row.admission)
			probe.claims.ExpiresAt = now.Add(row.token)
			originalAdmission := probe.resolution.Admission

			result, err := flow.Finish(t.Context(), state, browser, "single-use-provider-code")
			if row.err != nil {
				require.ErrorIs(t, err, row.err)
				require.Nil(t, probe.completion, "an unusable window must fail before persistence")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, probe.completion)
			require.Equal(t, now.Add(row.want), result.Session.ExpiresAt)
			require.Equal(t, result.Session.ExpiresAt, probe.completion.Session.ExpiresAt)
			require.Equal(t, originalAdmission, result.Session.Admission)
			require.False(t, result.Session.ExpiresAt.After(originalAdmission.ValidUntil))
			require.False(t, result.Session.ExpiresAt.After(probe.claims.ExpiresAt))
		})
	}
}

// TestCentralRegistrationRetriesExactBinding models a lost successful callback
// response. Only an existing exact binding can bypass creation requirements, and
// a later authoritative commit rejection must still prevent a browser session.
func TestCentralRegistrationRetriesExactBinding(t *testing.T) {
	for _, row := range []struct {
		name       string // isolated registration retry scenario
		bound      bool   // preflight observes exact ownership
		bindingErr error  // preflight refusal or unavailable storage
		commitErr  error  // authoritative transaction refusal after preflight
		want       error  // expected callback failure category
	}{
		{name: "existing binding", bound: true},
		{name: "new account still needs invitation", want: ErrOAuthInvitationRequired},
		{name: "different provider identity", bindingErr: ErrCentralConflict, want: ErrCentralConflict},
		{name: "binding read unavailable", bindingErr: ErrCentralUnavailable, want: ErrCentralUnavailable},
		{name: "binding disappeared before commit", bound: true, commitErr: ErrCentralEvidenceInvalid, want: ErrCentralEvidenceInvalid},
	} {
		t.Run(row.name, func(t *testing.T) {
			flow, probe, state, browser, _ := centralLoginFixture(t, CentralIntentRegister)
			probe.bound, probe.bindingErr, probe.commitErr = row.bound, row.bindingErr, row.commitErr
			flow.Auth = &AuthService{AuthDependencies: &AuthDependencies{Settings: &centralRegistrationSettings{}}}
			defaultReads := 0
			flow.SignupDefaults = func(context.Context) (*AuthSourceDefaultSettings, error) {
				defaultReads++
				return &AuthSourceDefaultSettings{}, nil
			}
			result, err := flow.Finish(t.Context(), state, browser, "single-use-provider-code")
			require.True(t, probe.checkedBinding)
			if row.want != nil {
				require.ErrorIs(t, err, row.want)
				require.Empty(t, result.Secret)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, result.Secret)
			}
			if row.bound || row.bindingErr != nil {
				require.Zero(t, defaultReads, "existing ownership must not repeat signup policy reads")
			} else {
				require.Equal(t, 1, defaultReads)
			}
			if row.bound {
				require.NotNil(t, probe.completion)
				require.Nil(t, probe.completion.NewUser)
				require.Nil(t, probe.completion.Artifacts)
			} else {
				require.Nil(t, probe.completion)
			}
		})
	}
}

// TestCentralRegistrationPreservesDefaultsOutage distinguishes a failed policy
// read from an established verified-email requirement. Both remain failures, with
// the unavailable category reserved for the failed read.
func TestCentralRegistrationPreservesDefaultsOutage(t *testing.T) {
	for _, row := range []struct {
		name  string // isolated signup policy outcome
		err   error  // repository read failure result
		force bool   // successful read requires verified email
		want  error  // expected stable callback category
	}{
		{"read failure", errors.New("fixture settings outage"), false, ErrCentralUnavailable},
		{"verified email required", nil, true, ErrCentralProofRequired},
	} {
		t.Run(row.name, func(t *testing.T) {
			flow := &CentralFlow{
				Auth: &AuthService{AuthDependencies: &AuthDependencies{Settings: &centralRegistrationSettings{}}},
				SignupDefaults: func(context.Context) (*AuthSourceDefaultSettings, error) {
					return &AuthSourceDefaultSettings{ForceEmailOnThirdPartySignup: row.force}, row.err
				},
			}
			_, _, _, err := flow.prepareRegistration(t.Context(), CentralLoginIntent{}, &OIDCVerifiedClaims{}, &OIDCUserInfoClaims{}, CentralAccountReference{})
			require.ErrorIs(t, err, row.want)
		})
	}
}

// centralLoginFixture prepares independent provider observations and a consumed
// browser intent for the production completion method. Its transparent cipher
// is a test boundary and makes no assertion about encrypted storage.
func centralLoginFixture(t *testing.T, intent string) (*CentralFlow, *centralLoginProbe, string, string, time.Time) {
	t.Helper()
	policy, session, status, now := centralFixture()
	state, browser := strings.Repeat("a", 64), strings.Repeat("b", 64)
	issuer := "https://identity.example.test/realms/test"
	transactionIntent := CentralLoginIntent{Intent: intent, StateDigest: CentralSecretDigest(state), BrowserDigest: CentralSecretDigest(browser), Issuer: issuer, ClientID: "gettok-test", AuthorityIncarnation: policy.AuthorityIncarnation, Nonce: "test-nonce", Verifier: "test-verifier"}
	encoded, err := json.Marshal(transactionIntent)
	require.NoError(t, err)
	authenticatedAt := session.Admission.AuthenticatedAt
	probe := &centralLoginProbe{
		transaction: CentralLoginTransaction{StateDigest: transactionIntent.StateDigest, BrowserDigest: transactionIntent.BrowserDigest, Ciphertext: string(encoded), CreatedAt: now, ExpiresAt: now.Add(CentralAdmissionBudget)},
		claims:      OIDCVerifiedClaims{Issuer: issuer, Subject: "verified-subject", AuthenticatedAt: &authenticatedAt, ExpiresAt: now.Add(10 * time.Minute)},
		resolution:  CentralResolution{Status: status, Admission: session.Admission},
	}
	flow := &CentralFlow{Options: CentralLoginOptions{Policy: policy, OIDC: OIDCOAuthOptions{IssuerURL: issuer, ClientID: transactionIntent.ClientID}}, Store: probe, Provider: probe, Authority: probe, Cipher: probe, Now: func() time.Time { return now }}
	return flow, probe, state, browser, now
}

// ConsumeLogin supplies the prepared transaction without modeling database consumption.
func (p *centralLoginProbe) ConsumeLogin(context.Context, string, string, time.Time) (CentralLoginTransaction, error) {
	return p.transaction, nil
}

// Decrypt exposes the prebuilt intent without claiming a cryptographic storage check.
func (p *centralLoginProbe) Decrypt(value string) (string, error) { return value, nil }

// ExchangeCode supplies disposable credentials to the callback's provider boundary.
func (p *centralLoginProbe) ExchangeCode(context.Context, OIDCOAuthOptions, string, string, string) (*OIDCTokenResponse, error) {
	return &OIDCTokenResponse{AccessToken: "test-access", IDToken: "test-id", TokenType: "Bearer"}, nil
}

// ValidateIDToken supplies the fixture's independently chosen signed identity observations.
func (p *centralLoginProbe) ValidateIDToken(context.Context, OIDCOAuthOptions, string, string) (*OIDCVerifiedClaims, error) {
	return &p.claims, nil
}

// FetchUserInfo supplies the matching subject without any verified email claim.
func (p *centralLoginProbe) FetchUserInfo(context.Context, OIDCOAuthOptions, *OIDCTokenResponse) (*OIDCUserInfoClaims, error) {
	return &OIDCUserInfoClaims{Subject: p.claims.Subject}, nil
}

// ResolveSelf returns the independently supplied account and original admission observations.
func (p *centralLoginProbe) ResolveSelf(context.Context, string, string) (CentralResolution, error) {
	return p.resolution, nil
}

// RecordAccountStatus accepts the callback observation without modeling durable publication.
func (p *centralLoginProbe) RecordAccountStatus(context.Context, CentralStatusEvidence) error {
	return nil
}

// HasBinding records the preflight and rejects arguments that differ from the
// verified fixture identity. Its configured result models only an observation;
// the independent commit outcome remains authoritative.
func (p *centralLoginProbe) HasBinding(_ context.Context, account CentralAccountReference, issuer, subject string) (bool, error) {
	p.checkedBinding = true
	if account != p.resolution.Status.Account || issuer != p.claims.Issuer || subject != p.claims.Subject {
		return false, ErrCentralConflict
	}
	return p.bound, p.bindingErr
}

// CompleteLogin captures the issued evidence before returning its configured
// final result. Successful fixtures retain the input session and never report a
// newly created user, so optional signup effects remain outside these tests.
func (p *centralLoginProbe) CompleteLogin(_ context.Context, input CentralLoginCompletion) (CentralLoginCommit, error) {
	p.completion = &input
	return CentralLoginCommit{Session: input.Session}, p.commitErr
}

// IsRegistrationEnabled permits account creation to reach the invitation requirement.
func (*centralRegistrationSettings) IsRegistrationEnabled(context.Context) bool { return true }

// IsInvitationCodeEnabled requires an unused invitation for each unbound identity.
func (*centralRegistrationSettings) IsInvitationCodeEnabled(context.Context) bool { return true }
