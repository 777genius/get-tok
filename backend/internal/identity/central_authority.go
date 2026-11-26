package identity

import "context"

// central_authority.go defines the product-facing authority port independently
// of Connect, generated messages or any HTTP framework. Human authentication
// resolves only the caller represented by the live upstream access credential.
// Its idempotency key identifies one command and cannot select another subject,
// consumer or account. Credentials travel in authenticated transport metadata.
//
// Workload status reads observe an already attached account through separately
// configured consumer credentials. They cannot create an attachment, impersonate
// a human, mint admission evidence or renew the proof carried by an existing
// product session. Adapters map unknown protocol values and unavailable remote
// observations into errors, leaving the consumer's policy and persistence layer
// responsible for monotone status publication and local session admission.

// CentralIdentityAuthority resolves humans and reads previously attached account status.
type CentralIdentityAuthority interface {
	// ResolveSelf derives subject and consumer from a live human credential.
	// The command key provides retry identity without selecting any account.
	ResolveSelf(ctx context.Context, humanCredential, commandID string) (CentralResolution, error)
	// GetAccountStatus uses separate workload authority for read-only status.
	// It cannot renew the admission proof frozen into a product session.
	GetAccountStatus(ctx context.Context, account CentralAccountReference) (CentralStatusEvidence, error)
}
