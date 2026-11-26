package authctx

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/server/httpx"
)

// central.go lets product resource handlers require qualified authentication
// before applying their existing role and ownership rules. The callback is
// installed only after central cookie authentication has obtained and published
// fresh authority evidence. Its captured session retains original counters and
// proof expiry, so a later resource check cannot upgrade authentication by
// looking at a newer status snapshot or a local role.
//
// Legacy and machine callers retain their existing authentication behavior.
// A principal explicitly marked central without the accompanying verifier is
// rejected rather than treated as legacy. Product handlers can query assurance
// when choosing a strictly personal data projection, or require it and stop the
// response before returning organizational records or accepting a protected
// mutation. These helpers confer no local product authorization.

const centralAccessKey = "identity_central_access" // private request-scoped assurance callback

// SetCentralAccess retains the verified session's finite assurance evaluator.
func SetCentralAccess(c *gin.Context, check func(identity.CentralAccessClass) error) {
	c.Set(centralAccessKey, check)
}

// IsCentral reports the immutable middleware principal's authentication kind.
func IsCentral(c *gin.Context) bool {
	principal, ok := GetPrincipal(c)
	return ok && principal.CredentialKind == "central"
}

// CentralAccessError evaluates assurance without writing a response, for strict personal projections.
func CentralAccessError(c *gin.Context, required identity.CentralAccessClass) error {
	if !IsCentral(c) {
		return nil
	}
	value, exists := c.Get(centralAccessKey)
	check, ok := value.(func(identity.CentralAccessClass) error)
	if !exists || !ok || check == nil {
		return identity.ErrCentralProofRequired
	}
	return check(required)
}

// RequireCentralAccess stops an unqualified central request before protected resource use.
// Legacy callers continue through their unchanged product permission checks.
func RequireCentralAccess(c *gin.Context, required identity.CentralAccessClass) bool {
	if CentralAccessError(c, required) == nil {
		return true
	}
	httpx.AbortWithError(c, http.StatusForbidden, "CENTRAL_PROOF_REQUIRED", "Additional account verification is required for this action.")
	return false
}
