package identity

import (
	"errors"
	"strings"
	"time"
)

// central_session.go checks central identity evidence against one immutable
// product session and combines authoritative observations without losing
// revocation history. A session retains the account epoch, attachment generation
// and authentication evidence accepted at issuance. Later status observations
// can invalidate those facts, but cannot replace them or extend the session's
// authentication lifetime.
//
// Product roles, balances and team membership remain local decisions. These
// checks establish whether the central account and issued session can still
// authenticate. Organizational access additionally requires the exact qualified
// continuity policy configured by the application; ordinary provider login and
// familiar acr or amr labels cannot satisfy that requirement. Storage adapters
// serialize status publication before applying these rules to requests.

const (
	// These lifecycle values confer no product role, entitlement or membership.
	CentralEligibilityUnknown CentralEligibility = iota
	CentralEligibilityActive
	CentralEligibilitySuspended
	CentralEligibilityClosed

	// The source observation window reserves clock uncertainty inside the total
	// status budget. Authentication has a separate absolute, nonrenewable horizon.
	CentralStatusBudget       = time.Minute
	CentralClockUncertainty   = 5 * time.Second
	CentralSourceLease        = CentralStatusBudget - CentralClockUncertainty
	CentralAdmissionBudget    = 5 * time.Minute
	CentralFlowAgeLimit       = 8 * time.Hour
	CentralContinuityAgeLimit = time.Hour
	CentralSensitiveAgeLimit  = 5 * time.Minute
)

// These profiles represent qualified server admission mechanisms, never labels
// inferred by consumers from unqualified upstream authentication observations.
//
//nolint:decorder // Separate const blocks keep each iota sequence starting at zero.
const (
	CentralProfileUnknown CentralAdmissionProfile = iota
	CentralProfileProviderSession
	CentralProfileIndependentContinuity
)

// These access classes select authentication assurance before product permissions.
//
//nolint:decorder // Separate const blocks keep each iota sequence starting at zero.
const (
	CentralAccessOrdinary CentralAccessClass = iota
	CentralAccessOrganizational
	CentralAccessSensitive
)

var (
	// Separate errors preserve unavailable evidence, rejected authentication and
	// insufficient assurance, so adapters cannot turn uncertainty into access.
	ErrCentralEvidenceInvalid = errors.New("central identity evidence is invalid")
	ErrCentralSessionExpired  = errors.New("central identity session requires authentication")
	ErrCentralAccountInactive = errors.New("central identity account is not active")
	ErrCentralProofRequired   = errors.New("central identity continuity proof is required")
	ErrCentralEvidenceStale   = errors.New("central identity observation is stale")
	ErrCentralConflict        = errors.New("central identity binding conflicts")
	ErrCentralUnavailable     = errors.New("central identity is unavailable")
)

// CentralEligibility describes account lifecycle observed by its trusted identity authority.
type CentralEligibility uint8

// CentralAdmissionProfile identifies the qualified mechanism that admitted one session.
type CentralAdmissionProfile uint8

// CentralAccessClass selects authentication assurance before local resource authorization runs.
type CentralAccessClass uint8

// CentralAccountReference identifies one account across a configured authority incarnation.
type CentralAccountReference struct {
	AccountID            string // immutable central account identifier
	AuthorityIncarnation string // configured authority continuity identifier
}

// CentralStatusEvidence carries one authenticated authoritative account state observation.
type CentralStatusEvidence struct {
	Account     CentralAccountReference // observed central account reference
	ConsumerID  string                  // attached product consumer identifier
	Eligibility CentralEligibility      // observed account lifecycle state
	// Revision orders complete observations. Security and attachment counters
	// stay pinned to issued sessions; current status cannot upgrade those sessions.
	Revision             uint64 // authoritative account state revision
	SecurityEpoch        uint64 // current account security epoch
	AttachmentGeneration uint64 // current consumer attachment generation
	// Cutoffs reject authentication completed at or before their timestamps.
	// A zero value records the absence of an established cutoff.
	AuthenticationCutoff time.Time // account authentication invalidation cutoff
	ReattachmentCutoff   time.Time // consumer reattachment invalidation cutoff
	ObservedAt           time.Time // authoritative database observation time
	ValidUntil           time.Time // absolute source evidence expiry
}

// CentralSessionAdmission contains authentication facts that account status cannot renew.
type CentralSessionAdmission struct {
	AuthoritySessionID string                  // qualified provider session identifier
	Profile            CentralAdmissionProfile // qualified admission mechanism profile
	PolicyID           string                  // configured exact resource policy
	PolicyVersion      uint32                  // configured exact policy version
	AuthenticatedAt    time.Time               // verified actual flow authentication
	ValidUntil         time.Time               // nonrenewable authentication evidence expiry
}

// CentralResolution combines current account status and newly issued authentication evidence.
type CentralResolution struct {
	Status    CentralStatusEvidence   // authoritative attached account state
	Admission CentralSessionAdmission // original session admission evidence
}

// CentralSession records one server-owned product session without storing browser tokens.
type CentralSession struct {
	Digest      string                  // SHA-256 opaque cookie digest
	LocalUserID int64                   // unchanged product account identifier
	Account     CentralAccountReference // bound central account reference
	// Issued security and attachment counters are immutable. A mismatch requires
	// explicit authentication instead of silently rebasing an older product session.
	SecurityEpoch        uint64                  // issued account security epoch
	AttachmentGeneration uint64                  // issued consumer attachment generation
	Admission            CentralSessionAdmission // frozen authentication evidence
	CreatedAt            time.Time               // product session issuance time
	ExpiresAt            time.Time               // absolute product session expiry
	RevokedAt            *time.Time              // nil while locally unrevoked
}

// CentralConsumerPolicy pins trusted consumer, authority and qualified admission policies.
type CentralConsumerPolicy struct {
	ConsumerID            string // configured product consumer identifier
	AuthorityIncarnation  string // configured authority continuity identifier
	OrdinaryPolicyID      string // configured normal-login policy identifier
	OrdinaryPolicyVersion uint32 // configured normal-login policy version
	// Continuity policy stays unset until the actual independent mechanism
	// qualifies. A returned claim cannot enable either configuration value.
	ContinuityPolicyID      string // qualified continuity policy identifier
	ContinuityPolicyVersion uint32 // qualified continuity policy version
}

// ValidateCentralStatus checks identity, counter presence and the absolute
// observation budget. Request start is captured before the authority call;
// neither transit time nor response arrival creates a replacement lease.
func ValidateCentralStatus(policy CentralConsumerPolicy, status CentralStatusEvidence, requestStartedAt, now time.Time) error {
	if !centralIdentifier(policy.ConsumerID) || !centralIdentifier(policy.OrdinaryPolicyID) || policy.OrdinaryPolicyVersion == 0 ||
		!centralIdentifier(status.Account.AccountID) || !centralIdentifier(status.Account.AuthorityIncarnation) ||
		status.Account.AuthorityIncarnation != policy.AuthorityIncarnation || status.ConsumerID != policy.ConsumerID ||
		status.Revision == 0 || status.SecurityEpoch == 0 || status.AttachmentGeneration == 0 {
		return ErrCentralEvidenceInvalid
	}
	if status.Eligibility != CentralEligibilityActive && status.Eligibility != CentralEligibilitySuspended && status.Eligibility != CentralEligibilityClosed {
		return ErrCentralEvidenceInvalid
	}
	if requestStartedAt.IsZero() || now.Before(requestStartedAt) || status.ObservedAt.IsZero() || status.ValidUntil.IsZero() ||
		status.ObservedAt.After(now.Add(CentralClockUncertainty)) || !status.ValidUntil.After(status.ObservedAt) ||
		status.ValidUntil.Sub(status.ObservedAt) > CentralSourceLease {
		return ErrCentralEvidenceInvalid
	}
	// Transit and local scheduling consume the existing source window. Using
	// request start prevents a delayed response from creating another full lease.
	if !now.Add(CentralClockUncertainty).Before(status.ValidUntil) || !now.Before(requestStartedAt.Add(CentralStatusBudget)) {
		return ErrCentralEvidenceStale
	}
	return nil
}

// MergeCentralStatus preserves the newest coherent observation for one account.
// Callers serialize persistence with this decision; delayed delivery cannot undo
// a previously observed suspension, closure, epoch or attachment generation.
//
// Equal revisions can refresh observation times only. Larger revisions cannot
// decrease security fences or reopen closed accounts, and stale revisions return
// the stored value. Request admission still checks the resulting freshness, so
// retaining a denial never grants permission to reuse an expired observation.
func MergeCentralStatus(current, incoming CentralStatusEvidence) (CentralStatusEvidence, error) {
	if current.Account != incoming.Account || current.ConsumerID != incoming.ConsumerID {
		return CentralStatusEvidence{}, ErrCentralEvidenceInvalid
	}
	if incoming.Revision < current.Revision {
		return current, nil
	}
	if incoming.SecurityEpoch < current.SecurityEpoch || incoming.AttachmentGeneration < current.AttachmentGeneration ||
		incoming.AuthenticationCutoff.Before(current.AuthenticationCutoff) || incoming.ReattachmentCutoff.Before(current.ReattachmentCutoff) ||
		(current.Eligibility == CentralEligibilityClosed && incoming.Eligibility != CentralEligibilityClosed) {
		return CentralStatusEvidence{}, ErrCentralEvidenceInvalid
	}
	if incoming.Revision == current.Revision && (incoming.Eligibility != current.Eligibility ||
		incoming.SecurityEpoch != current.SecurityEpoch || incoming.AttachmentGeneration != current.AttachmentGeneration ||
		!incoming.AuthenticationCutoff.Equal(current.AuthenticationCutoff) || !incoming.ReattachmentCutoff.Equal(current.ReattachmentCutoff)) {
		return CentralStatusEvidence{}, ErrCentralEvidenceInvalid
	}
	if incoming.Revision == current.Revision && !incoming.ObservedAt.After(current.ObservedAt) {
		return current, nil
	}
	return incoming, nil
}

// AuthorizeCentralSession checks immutable issuance against current account
// evidence before product authorization. Organizational access requires the
// exact qualified continuity policy; ordinary provider login cannot substitute.
//
// This decision never extends a session, changes issued counters or derives
// factor age from token issuance. Reauthentication follows every applicable
// cutoff or counter change. Storage supplies a fresh session after publishing
// status, keeping a completed local logout effective during concurrent refresh.
func AuthorizeCentralSession(policy CentralConsumerPolicy, session CentralSession, status CentralStatusEvidence, requestStartedAt, now time.Time, access CentralAccessClass) error {
	if err := ValidateCentralStatus(policy, status, requestStartedAt, now); err != nil {
		return err
	}
	if session.LocalUserID <= 0 || session.Account != status.Account || session.RevokedAt != nil ||
		session.CreatedAt.IsZero() || session.CreatedAt.After(now.Add(CentralClockUncertainty)) ||
		!session.ExpiresAt.After(session.CreatedAt) || !now.Add(CentralClockUncertainty).Before(session.ExpiresAt) ||
		session.ExpiresAt.Sub(session.CreatedAt) > CentralAdmissionBudget || session.ExpiresAt.After(session.Admission.ValidUntil) {
		return ErrCentralSessionExpired
	}
	if status.Eligibility != CentralEligibilityActive {
		return ErrCentralAccountInactive
	}
	if session.SecurityEpoch != status.SecurityEpoch || session.AttachmentGeneration != status.AttachmentGeneration {
		return ErrCentralSessionExpired
	}
	proof := session.Admission
	if !centralIdentifier(proof.AuthoritySessionID) || proof.AuthenticatedAt.IsZero() || proof.AuthenticatedAt.After(now.Add(CentralClockUncertainty)) ||
		now.Sub(proof.AuthenticatedAt) > CentralFlowAgeLimit || !now.Add(CentralClockUncertainty).Before(proof.ValidUntil) ||
		(!status.AuthenticationCutoff.IsZero() && !proof.AuthenticatedAt.After(status.AuthenticationCutoff)) ||
		(!status.ReattachmentCutoff.IsZero() && !proof.AuthenticatedAt.After(status.ReattachmentCutoff)) {
		return ErrCentralSessionExpired
	}
	ordinary := proof.Profile == CentralProfileProviderSession && proof.PolicyID == policy.OrdinaryPolicyID && proof.PolicyVersion == policy.OrdinaryPolicyVersion && proof.PolicyVersion > 0
	continuity := policy.ContinuityPolicyID != "" && policy.ContinuityPolicyVersion > 0 &&
		proof.Profile == CentralProfileIndependentContinuity && proof.PolicyID == policy.ContinuityPolicyID && proof.PolicyVersion == policy.ContinuityPolicyVersion
	if !ordinary && !continuity {
		return ErrCentralProofRequired
	}
	if (access == CentralAccessOrganizational || access == CentralAccessSensitive) && (!continuity || now.Sub(proof.AuthenticatedAt) > CentralContinuityAgeLimit) {
		return ErrCentralProofRequired
	}
	if access == CentralAccessSensitive && now.Sub(proof.AuthenticatedAt) > CentralSensitiveAgeLimit {
		return ErrCentralProofRequired
	}
	if access != CentralAccessOrdinary && access != CentralAccessOrganizational && access != CentralAccessSensitive {
		return ErrCentralEvidenceInvalid
	}
	return nil
}

// centralIdentifier rejects unbounded, padded or control-bearing trusted identifiers.
// It preserves opaque identifier case and does not invent normalization rules.
func centralIdentifier(value string) bool {
	return value != "" && len(value) <= 1024 && value == strings.TrimSpace(value) &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}
