package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	identityv1 "github.com/agent-teams-ai/identity/packages/contracts/gen/go/identity/v1"
	"github.com/agent-teams-ai/identity/packages/contracts/gen/go/identity/v1/identityv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// central_identity.go adapts the generated Identity contract to product-owned
// authentication policy. Human authentication is used only for ResolveSelf;
// subsequent account observations use a separate confidential workload client.
// The workload grant cannot select a human subject or renew session admission.
// Core types contain no generated messages or Connect transport dependencies.
//
// Requests have bounded duration and response size, never follow redirects, and
// return stable local errors without server bodies or credentials. Conversion
// rejects unknown enums and malformed timestamps instead of silently accepting
// protocol defaults. A short workload-token cache reduces repeated token grants;
// its deadline is independent of account-status and human-proof acceptance.

// CentralAuthorityOptions supplies validated service endpoints and one consumer workload.
type CentralAuthorityOptions struct {
	BaseURL              string // exact Identity HTTPS origin and optional base path
	TokenURL             string // exact trusted workload token endpoint
	WorkloadClientID     string // separate consumer-scoped workload client
	WorkloadClientSecret string // server-held confidential client credential
}

// CentralIdentityClient owns generated RPC transport and bounded workload custody.
type CentralIdentityClient struct {
	client     identityv1connect.IdentityServiceClient // generated version-pinned protocol client
	http       *http.Client                            // no-redirect, finite-time credential transport
	options    CentralAuthorityOptions                 // immutable validated endpoint and client configuration
	mu         sync.Mutex                              // serializes workload grant refresh and cache publication
	token      string                                  // in-memory workload access credential, never a human token
	tokenUntil time.Time                               // conservative cache deadline before grant expiration
}

// NewCentralIdentityClient constructs bounded generated RPC and workload
// transports after deployment validation. TLS verification stays enabled,
// redirects are not followed, and loopback HTTP is reserved for the explicit
// TEST configuration.
func NewCentralIdentityClient(options CentralAuthorityOptions) *CentralIdentityClient {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &CentralIdentityClient{options: options, http: client, client: identityv1connect.NewIdentityServiceClient(client, options.BaseURL, connect.WithReadMaxBytes(65536))}
}

// ResolveSelf sends the live human credential only through authenticated
// metadata. The versioned request carries its idempotency key while the
// authority derives issuer, subject and consumer; returned unknown wire values
// fail closed.
func (c *CentralIdentityClient) ResolveSelf(ctx context.Context, human, command string) (identity.CentralResolution, error) {
	request := connect.NewRequest(&identityv1.ResolveSelfRequest{IdempotencyKey: command})
	request.Header().Set("Authorization", "Bearer "+human)
	response, err := c.client.ResolveSelf(ctx, request)
	if err != nil {
		return identity.CentralResolution{}, centralRPCError(err)
	}
	status, err := centralStatus(response.Msg.GetStatus())
	if err != nil {
		return identity.CentralResolution{}, err
	}
	admission, err := centralAdmission(response.Msg.GetAdmission())
	return identity.CentralResolution{Status: status, Admission: admission}, err
}

// GetAccountStatus uses a separate workload credential to read the exact
// attached account reference. It rejects a contradictory returned reference,
// and its evidence cannot renew the original session counters or human proof
// deadline.
func (c *CentralIdentityClient) GetAccountStatus(ctx context.Context, account identity.CentralAccountReference) (identity.CentralStatusEvidence, error) {
	credential, err := c.workloadCredential(ctx)
	if err != nil {
		return identity.CentralStatusEvidence{}, err
	}
	request := connect.NewRequest(&identityv1.GetAccountStatusRequest{Account: &identityv1.AccountReference{AccountId: account.AccountID, AuthorityIncarnation: account.AuthorityIncarnation}})
	request.Header().Set("Authorization", "Bearer "+credential)
	response, err := c.client.GetAccountStatus(ctx, request)
	if err != nil {
		return identity.CentralStatusEvidence{}, centralRPCError(err)
	}
	status, err := centralStatus(response.Msg.GetStatus())
	if err == nil && status.Account != account {
		err = identity.ErrCentralEvidenceInvalid
	}
	return status, err
}

// workloadCredential obtains and briefly caches a dedicated client-credentials
// grant under a mutex shared by callers. Refresh failure never selects an
// expired token or the human client. The cache deadline starts before the
// request so network time consumes the existing budget; it is capped at one
// minute and at least five seconds before reported provider expiry. This
// deadline governs token transport only and cannot extend account-status
// evidence or an authenticated browser session.
func (c *CentralIdentityClient) workloadCredential(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	started := time.Now().UTC()
	if c.token != "" && started.Before(c.tokenUntil) {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"identity.status:read"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.options.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", identity.ErrCentralUnavailable
	}
	request.SetBasicAuth(url.QueryEscape(c.options.WorkloadClientID), url.QueryEscape(c.options.WorkloadClientSecret))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return "", identity.ErrCentralUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || response.StatusCode != http.StatusOK || len(data) > 65536 {
		return "", identity.ErrCentralUnavailable
	}
	var grant struct {
		AccessToken string `json:"access_token"` // confidential workload access grant
		TokenType   string `json:"token_type"`   // required Bearer scheme
		ExpiresIn   int64  `json:"expires_in"`   // provider lifetime in seconds
	}
	if json.Unmarshal(data, &grant) != nil || grant.AccessToken == "" || len(grant.AccessToken) > 16384 || strings.ContainsAny(grant.AccessToken, " \t\r\n") || !strings.EqualFold(grant.TokenType, "Bearer") || grant.ExpiresIn <= 5 {
		return "", identity.ErrCentralUnavailable
	}
	lifetime := min(grant.ExpiresIn-5, int64(60))
	c.token, c.tokenUntil = grant.AccessToken, started.Add(time.Duration(lifetime)*time.Second)
	if !time.Now().Before(c.tokenUntil) {
		return "", identity.ErrCentralUnavailable
	}
	return c.token, nil
}

// centralStatus converts the generated observation without supplying defaults
// for absent required messages or unknown enums. The core separately validates
// consumer, counter presence and contextual time bounds before any request
// admission.
func centralStatus(value *identityv1.AccountStatusEvidence) (identity.CentralStatusEvidence, error) {
	if value == nil || value.Account == nil {
		return identity.CentralStatusEvidence{}, identity.ErrCentralEvidenceInvalid
	}
	status := identity.CentralStatusEvidence{Account: identity.CentralAccountReference{AccountID: value.Account.AccountId, AuthorityIncarnation: value.Account.AuthorityIncarnation}, ConsumerID: value.ConsumerId, Revision: value.AccountRevision, SecurityEpoch: value.SecurityEpoch, AttachmentGeneration: value.AttachmentGeneration}
	switch value.Eligibility {
	case identityv1.AccountEligibility_ACCOUNT_ELIGIBILITY_ACTIVE:
		status.Eligibility = identity.CentralEligibilityActive
	case identityv1.AccountEligibility_ACCOUNT_ELIGIBILITY_SUSPENDED:
		status.Eligibility = identity.CentralEligibilitySuspended
	case identityv1.AccountEligibility_ACCOUNT_ELIGIBILITY_CLOSED:
		status.Eligibility = identity.CentralEligibilityClosed
	default:
		return status, identity.ErrCentralEvidenceInvalid
	}
	var err error
	status.ObservedAt, err = centralTimestamp(value.ObservedAt, true)
	if err != nil {
		return status, err
	}
	status.ValidUntil, err = centralTimestamp(value.ValidUntil, true)
	if err != nil {
		return status, err
	}
	status.AuthenticationCutoff, err = centralTimestamp(value.AuthenticationCutoff, false)
	if err != nil {
		return status, err
	}
	status.ReattachmentCutoff, err = centralTimestamp(value.ReattachmentCutoff, false)
	return status, err
}

// centralAdmission retains the exact qualified profile, policy, provider
// session and authentication timestamps. Unknown profiles and malformed
// required fields return errors; configuration, rather than received claims,
// determines whether a stronger policy is enabled.
func centralAdmission(value *identityv1.SessionAdmission) (identity.CentralSessionAdmission, error) {
	if value == nil {
		return identity.CentralSessionAdmission{}, identity.ErrCentralEvidenceInvalid
	}
	admission := identity.CentralSessionAdmission{AuthoritySessionID: value.AuthoritySessionId, PolicyID: value.PolicyId, PolicyVersion: value.PolicyVersion}
	switch value.Profile {
	case identityv1.AdmissionProfile_ADMISSION_PROFILE_PROVIDER_SESSION_CONTROL_V1:
		admission.Profile = identity.CentralProfileProviderSession
	case identityv1.AdmissionProfile_ADMISSION_PROFILE_INDEPENDENT_CONTINUITY_V1:
		admission.Profile = identity.CentralProfileIndependentContinuity
	default:
		return admission, identity.ErrCentralEvidenceInvalid
	}
	var err error
	admission.AuthenticatedAt, err = centralTimestamp(value.AuthenticatedAt, true)
	if err != nil {
		return admission, err
	}
	admission.ValidUntil, err = centralTimestamp(value.ValidUntil, true)
	return admission, err
}

// centralTimestamp converts a valid protobuf timestamp to UTC. Required
// missing values fail, while omitted optional cutoffs remain absent; an
// explicitly supplied malformed timestamp never becomes an absent or default
// cutoff.
func centralTimestamp(value *timestamppb.Timestamp, required bool) (time.Time, error) {
	if value == nil {
		if required {
			return time.Time{}, identity.ErrCentralEvidenceInvalid
		}
		return time.Time{}, nil
	}
	if value.CheckValid() != nil {
		return time.Time{}, identity.ErrCentralEvidenceInvalid
	}
	return value.AsTime().UTC(), nil
}

// centralRPCError converts recognized protocol semantics to stable local
// authentication errors without retaining server diagnostics. Explicit service
// failures remain unavailable, while rejected or unknown authentication
// evidence cannot grant access or trigger a legacy fallback.
func centralRPCError(err error) error {
	if connect.CodeOf(err) == connect.CodeUnavailable || connect.CodeOf(err) == connect.CodeDeadlineExceeded || connect.CodeOf(err) == connect.CodeResourceExhausted || connect.CodeOf(err) == connect.CodeInternal {
		return identity.ErrCentralUnavailable
	}
	if failure, ok := errors.AsType[*connect.Error](err); ok {
		for _, detail := range failure.Details() {
			decoded, decodeErr := detail.Value()
			if decodeErr != nil {
				return identity.ErrCentralEvidenceInvalid
			}
			value, ok := decoded.(*identityv1.IdentityErrorDetail)
			if !ok {
				continue
			}
			switch value.Reason {
			case identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_ACCOUNT_SUSPENDED, identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_ACCOUNT_CLOSED:
				return identity.ErrCentralAccountInactive
			case identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_INSUFFICIENT_PROOF:
				return identity.ErrCentralProofRequired
			case identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_CONFLICT:
				return identity.ErrCentralConflict
			case identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_ADMISSION_EXPIRED, identityv1.IdentityErrorReason_IDENTITY_ERROR_REASON_AUTHENTICATION_REQUIRED_AFTER_CUTOFF:
				return identity.ErrCentralSessionExpired
			default:
				return identity.ErrCentralEvidenceInvalid
			}
		}
	}
	return identity.ErrCentralEvidenceInvalid
}
