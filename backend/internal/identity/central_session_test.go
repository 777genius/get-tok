package identity

import (
	"errors"
	"testing"
	"time"
)

// central_session_test.go exercises authentication boundaries without network or
// storage fixtures. Every case starts from the same explicit clock, authority,
// consumer and issued session, then changes one security fact. The cases cover
// missing observations, elapsed time, independent-factor admission and monotone
// account-state publication because those facts determine whether a browser
// session can continue using product data.
//
// Status refresh is tested separately from authentication renewal. The tests
// preserve the original proof expiry and issued counters while delivering newer
// account observations, including reordered denials and equal-revision changes.
// Persistence adapters must apply these decisions under their own transaction
// locks; this suite checks the pure policy used inside that commit scope.

// centralFixture returns independent policy, session and observation values with
// a fixed clock. Their generous remaining bounds isolate each changed invariant.
func centralFixture() (CentralConsumerPolicy, CentralSession, CentralStatusEvidence, time.Time) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	policy := CentralConsumerPolicy{ConsumerID: "gettok", AuthorityIncarnation: "authority-1", OrdinaryPolicyID: "gettok-ordinary-login", OrdinaryPolicyVersion: 1}
	status := CentralStatusEvidence{Account: CentralAccountReference{AccountID: "account-1", AuthorityIncarnation: "authority-1"}, ConsumerID: "gettok", Eligibility: CentralEligibilityActive, Revision: 1, SecurityEpoch: 1, AttachmentGeneration: 1, ObservedAt: now, ValidUntil: now.Add(CentralSourceLease)}
	session := CentralSession{LocalUserID: 42, Account: status.Account, SecurityEpoch: 1, AttachmentGeneration: 1, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute), Admission: CentralSessionAdmission{AuthoritySessionID: "qualified-session-1", Profile: CentralProfileProviderSession, PolicyID: policy.OrdinaryPolicyID, PolicyVersion: 1, AuthenticatedAt: now.Add(-time.Hour), ValidUntil: now.Add(4 * time.Minute)}}
	return policy, session, status, now
}

// TestCentralAdmissionKeepsQualifiedProfilesSeparate admits ordinary activity
// while refusing organizational use until both mechanism and configured policy
// match. Sensitive actions retain their shorter actual-factor age requirement.
func TestCentralAdmissionKeepsQualifiedProfilesSeparate(t *testing.T) {
	policy, session, status, now := centralFixture()
	if err := AuthorizeCentralSession(policy, session, status, now, now, CentralAccessOrdinary); err != nil {
		t.Fatal(err)
	}
	if err := AuthorizeCentralSession(policy, session, status, now, now, CentralAccessOrganizational); !errors.Is(err, ErrCentralProofRequired) {
		t.Fatalf("ordinary session admitted organization: %v", err)
	}
	session.Admission.Profile = CentralProfileIndependentContinuity
	session.Admission.PolicyID = "gettok-protected-organizational"
	session.Admission.AuthenticatedAt = now.Add(-time.Minute)
	if err := AuthorizeCentralSession(policy, session, status, now, now, CentralAccessOrganizational); !errors.Is(err, ErrCentralProofRequired) {
		t.Fatalf("unqualified profile enabled itself: %v", err)
	}
	policy.ContinuityPolicyID = session.Admission.PolicyID
	policy.ContinuityPolicyVersion = 1
	if err := AuthorizeCentralSession(policy, session, status, now, now, CentralAccessSensitive); err != nil {
		t.Fatal(err)
	}
	session.Admission.AuthenticatedAt = now.Add(-6 * time.Minute)
	if err := AuthorizeCentralSession(policy, session, status, now, now, CentralAccessSensitive); !errors.Is(err, ErrCentralProofRequired) {
		t.Fatalf("old factor admitted sensitive action: %v", err)
	}
	session.Admission.AuthenticatedAt = now.Add(-61 * time.Minute)
	if err := AuthorizeCentralSession(policy, session, status, now, now, CentralAccessOrganizational); !errors.Is(err, ErrCentralProofRequired) {
		t.Fatalf("old factor admitted organization: %v", err)
	}
}

// TestCentralAdmissionRejectsMissingAndChangedEvidence changes one required
// account or session invariant per case. None of these failures can fall back
// to a local JWT, an older snapshot or an unqualified admission profile.
func TestCentralAdmissionRejectsMissingAndChangedEvidence(t *testing.T) {
	cases := []struct {
		name   string                                                   // rejected authority case label
		change func(*CentralSession, *CentralStatusEvidence, time.Time) // isolated security fact mutation
	}{
		{"consumer", func(_ *CentralSession, s *CentralStatusEvidence, _ time.Time) { s.ConsumerID = "other" }},
		{"incarnation", func(_ *CentralSession, s *CentralStatusEvidence, _ time.Time) {
			s.Account.AuthorityIncarnation = "other"
		}},
		{"zero revision", func(_ *CentralSession, s *CentralStatusEvidence, _ time.Time) { s.Revision = 0 }},
		{"zero epoch", func(_ *CentralSession, s *CentralStatusEvidence, _ time.Time) { s.SecurityEpoch = 0 }},
		{"unknown lifecycle", func(_ *CentralSession, s *CentralStatusEvidence, _ time.Time) { s.Eligibility = 99 }},
		{"suspended", func(_ *CentralSession, s *CentralStatusEvidence, _ time.Time) {
			s.Eligibility = CentralEligibilitySuspended
		}},
		{"epoch changed", func(_ *CentralSession, s *CentralStatusEvidence, _ time.Time) { s.SecurityEpoch++ }},
		{"attachment changed", func(_ *CentralSession, s *CentralStatusEvidence, _ time.Time) { s.AttachmentGeneration++ }},
		{"account changed", func(s *CentralSession, _ *CentralStatusEvidence, _ time.Time) { s.Account.AccountID = "other" }},
		{"local logout", func(s *CentralSession, _ *CentralStatusEvidence, n time.Time) { s.RevokedAt = &n }},
		{"session expired", func(s *CentralSession, _ *CentralStatusEvidence, n time.Time) { s.ExpiresAt = n }},
		{"long session", func(s *CentralSession, _ *CentralStatusEvidence, _ time.Time) {
			s.CreatedAt = s.CreatedAt.Add(-time.Hour)
		}},
		{"missing auth time", func(s *CentralSession, _ *CentralStatusEvidence, _ time.Time) {
			s.Admission.AuthenticatedAt = time.Time{}
		}},
		{"future auth time", func(s *CentralSession, _ *CentralStatusEvidence, n time.Time) {
			s.Admission.AuthenticatedAt = n.Add(time.Minute)
		}},
		{"old flow", func(s *CentralSession, _ *CentralStatusEvidence, n time.Time) {
			s.Admission.AuthenticatedAt = n.Add(-9 * time.Hour)
		}},
		{"missing provider session", func(s *CentralSession, _ *CentralStatusEvidence, _ time.Time) { s.Admission.AuthoritySessionID = "" }},
		{"cutoff equality", func(s *CentralSession, e *CentralStatusEvidence, _ time.Time) {
			e.AuthenticationCutoff = s.Admission.AuthenticatedAt
		}},
		{"reattachment cutoff", func(s *CentralSession, e *CentralStatusEvidence, _ time.Time) {
			e.ReattachmentCutoff = s.Admission.AuthenticatedAt
		}},
		{"unknown profile", func(s *CentralSession, _ *CentralStatusEvidence, _ time.Time) { s.Admission.Profile = 99 }},
		{"wrong policy", func(s *CentralSession, _ *CentralStatusEvidence, _ time.Time) { s.Admission.PolicyID = "other" }},
		{"stale source", func(_ *CentralSession, s *CentralStatusEvidence, n time.Time) {
			s.ObservedAt = n.Add(-time.Minute)
			s.ValidUntil = n.Add(-5 * time.Second)
		}},
		{"excess source lease", func(_ *CentralSession, s *CentralStatusEvidence, n time.Time) { s.ValidUntil = n.Add(time.Minute) }},
		{"clock margin", func(_ *CentralSession, s *CentralStatusEvidence, n time.Time) {
			s.ObservedAt = n.Add(-50 * time.Second)
			s.ValidUntil = n.Add(5 * time.Second)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, session, status, now := centralFixture()
			tc.change(&session, &status, now)
			if err := AuthorizeCentralSession(policy, session, status, now, now, CentralAccessOrdinary); err == nil {
				t.Fatal("changed evidence unexpectedly authenticated")
			}
		})
	}
}

// TestCentralStatusCannotRenewAuthentication delivers a fresh status observation
// after the original session ends. It also rejects a delayed response even
// when that response carries an apparently fresh source window.
func TestCentralStatusCannotRenewAuthentication(t *testing.T) {
	policy, session, status, now := centralFixture()
	later := now.Add(5 * time.Minute)
	status.ObservedAt, status.ValidUntil = later, later.Add(CentralSourceLease)
	if err := AuthorizeCentralSession(policy, session, status, later, later, CentralAccessOrdinary); !errors.Is(err, ErrCentralSessionExpired) {
		t.Fatalf("status renewed proof: %v", err)
	}
	if err := ValidateCentralStatus(policy, status, later.Add(-time.Minute), later); !errors.Is(err, ErrCentralEvidenceStale) {
		t.Fatalf("delayed response received a new lease: %v", err)
	}
}

// TestCentralStatusMergePreservesRevocationHistory delivers reordered account
// observations and contradictory revisions. Higher revisions remain authoritative
// even when the database clock steps backward, while closed accounts stay closed.
func TestCentralStatusMergePreservesRevocationHistory(t *testing.T) {
	_, _, old, now := centralFixture()
	current := old
	current.Revision, current.Eligibility = 2, CentralEligibilitySuspended
	current.SecurityEpoch = 2
	got, err := MergeCentralStatus(current, old)
	if err != nil || got != current {
		t.Fatalf("stale ACTIVE replaced denial: %#v %v", got, err)
	}
	incoming := current
	incoming.Eligibility = CentralEligibilityActive
	if _, err := MergeCentralStatus(current, incoming); !errors.Is(err, ErrCentralEvidenceInvalid) {
		t.Fatalf("same revision changed facts: %v", err)
	}
	incoming.Revision++
	incoming.SecurityEpoch = 1
	if _, err := MergeCentralStatus(current, incoming); !errors.Is(err, ErrCentralEvidenceInvalid) {
		t.Fatalf("security counter rolled back: %v", err)
	}
	incoming = current
	incoming.Revision++
	incoming.ObservedAt = now.Add(-time.Second)
	got, err = MergeCentralStatus(current, incoming)
	if err != nil || got != incoming {
		t.Fatalf("clock step suppressed newer state: %#v %v", got, err)
	}
	current.Eligibility = CentralEligibilityClosed
	if _, err := MergeCentralStatus(current, incoming); !errors.Is(err, ErrCentralEvidenceInvalid) {
		t.Fatalf("closed account reopened: %v", err)
	}
}
