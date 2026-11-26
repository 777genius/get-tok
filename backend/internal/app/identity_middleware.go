package app

import (
	"context"

	"github.com/TokenFlux/TokenRouter/internal/audit"
	audithttp "github.com/TokenFlux/TokenRouter/internal/audit/httpapi"
	"github.com/TokenFlux/TokenRouter/internal/identity"
	identityhttp "github.com/TokenFlux/TokenRouter/internal/identity/httpapi"
	"github.com/TokenFlux/TokenRouter/internal/server/middleware"
)

// identity_middleware.go constructs authentication, step-up, and audit
// middleware from shared identity services. JWT and administrator
// authentication use the same assembled session and user services, with binding
// mismatches submitted to the audit recorder. Step-up middleware receives TOTP
// and runtime settings separately, while management audit middleware receives
// the shared redactor.

// identityAuthAudit converts authentication events to queued audit records.
type identityAuthAudit struct {
	audit *audit.AuditLogService /* authentication event audit sink */
}

// RecordBindingMismatch submits JWT binding-mismatch details to the audit
// service. It ignores the request context and uses the recorder's queue
// lifecycle; stopped or full recorders may discard the observation.
func (a identityAuthAudit) RecordBindingMismatch(_ context.Context, event identityhttp.BindingMismatchEvent) {
	a.audit.Record(&audit.AuditLog{ActorUserID: &event.UserID, ActorEmail: event.Email, ActorRole: event.Role, AuthMethod: audit.AuditAuthMethodJWT, Action: audit.AuditActionSessionBindingMismatch, Method: event.Method, Path: event.Path, ClientIP: event.ClientIP, UserAgent: event.UserAgent, StatusCode: 401})
}

// provideJWTAuth admits either an explicitly bound central browser session or
// legacy panel credentials. The central wrapper preserves ordinary product
// authorization, while legacy validation reads the durable central-management
// fence before accepting an older local token.
func provideJWTAuth(graph *identityAuthGraph, users *identity.UserService, settings *identity.RuntimeSettings, recorder *audit.AuditLogService, central *identityhttp.CentralHandler) identityhttp.JWTAuthMiddleware {
	legacy := identityhttp.JWTAuth(graph.Core, users, users, settings, identityAuthAudit{recorder})
	return identityhttp.JWTAuthMiddleware(central.Wrap(legacy, false))
}

// provideAdminAuth composes human administrator authentication with central
// assurance and existing role checks. MCP administrator credentials retain their
// separate machine policy outside the human session wrapper and do not acquire
// a browser continuity proof.
func provideAdminAuth(graph *identityAuthGraph, users *identity.UserService, settings *identity.RuntimeSettings, recorder *audit.AuditLogService, tokens *identity.MCPTokenService, central *identityhttp.CentralHandler) identityhttp.AdminAuthMiddleware {
	normal := central.Wrap(identityhttp.AdminAuth(graph.Core, users, settings, identityAuthAudit{recorder}), true)
	return identityhttp.AdminAuthMiddleware(identityhttp.MCPAdminAuth(tokens, normal))
}

// provideStepUpAuth binds session credentials, TOTP, and dynamic settings.
func provideStepUpAuth(totp *identity.TotpService, users *identity.UserService, settings *identity.RuntimeSettings) identityhttp.StepUpAuthMiddleware {
	return identityhttp.StepUpAuthMiddleware(identityhttp.StepUpAuth(totp, users, settings))
}

// provideAuditMiddleware constructs management audit logging with the shared
// recorder and redactor.
func provideAuditMiddleware(recorder *audit.AuditLogService, redactor *audit.Redactor) middleware.AuditLogMiddleware {
	return audithttp.NewAuditLogMiddleware(recorder, redactor)
}
