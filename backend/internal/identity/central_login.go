package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// central_login.go coordinates explicit central login, new registration and a
// separately enabled test migration profile. OAuth transactions keep their
// intent, nonce, PKCE verifier and any invitation inside authenticated server
// ciphertext. The browser receives only a random transaction cookie and later
// an opaque product session cookie. Human provider credentials are discarded
// after one live authority resolution and never become local JWT credentials.
//
// Account ownership remains a durable local decision. Login cannot silently
// create an account, registration cannot adopt an existing email owner, and
// migration requires fresh local credential proof. Storage atomically activates
// the sticky central-management fence with the immutable account binding and
// session. Workload status reads can invalidate this issued session but cannot
// renew its proof, counters or absolute authentication horizon.

const (
	CentralIntentLogin        = "login"                 // existing central account sign-in
	CentralIntentRegister     = "register"              // explicit new local registration
	CentralIntentBind         = "bind"                  // separately enabled existing-account migration
	CentralTestBindingProfile = "test-password-totp-v1" // unqualified default-off migration candidate
)

var (
	ErrCentralNotBound        = errors.New("central account has no local binding")
	ErrCentralBindingDisabled = errors.New("central account migration is unavailable")
)

// CentralLoginOptions supplies immutable provider and consumer deployment choices.
type CentralLoginOptions struct {
	Policy    CentralConsumerPolicy // trusted authority admission policy
	OIDC      OIDCOAuthOptions      // strictly validated central provider configuration
	Providers []string              // allowed upstream provider aliases
	// TestBindingProfile remains empty outside a deliberately enabled test setup.
	// The candidate does not establish an admitted production migration policy.
	TestBindingProfile string
}

// CentralOwnerProof records a fresh test-only credential ceremony for one owner.
type CentralOwnerProof struct {
	LocalUserID           int64     // unchanged local owner identifier
	CredentialFingerprint string    // observed password and factor fingerprint
	VerifiedAt            time.Time // actual completed local proof time
}

// CentralLoginIntent contains the encrypted intent retained through provider authentication.
type CentralLoginIntent struct {
	Intent               string             // explicit selected account operation
	StateDigest          string             // transaction state digest binding
	BrowserDigest        string             // transaction browser digest binding
	Issuer               string             // original trusted issuer configuration
	ClientID             string             // original trusted client configuration
	AuthorityIncarnation string             // original authority continuity configuration
	Nonce                string             // original OIDC nonce expectation
	Verifier             string             // original server-owned PKCE verifier
	InvitationCode       string             // optional encrypted registration invitation
	OwnerProof           *CentralOwnerProof // test-only prior local owner proof
}

// CentralLoginTransaction stores ciphertext and one-use browser transaction bounds.
type CentralLoginTransaction struct {
	StateDigest   string    // hashed OAuth state value
	BrowserDigest string    // hashed browser binding cookie
	Ciphertext    string    // authenticated encrypted intent payload
	CreatedAt     time.Time // transaction creation clock observation
	ExpiresAt     time.Time // absolute transaction expiration time
}

// CentralLoginCompletion supplies verified facts for one atomic local commit.
type CentralLoginCompletion struct {
	Intent  CentralLoginIntent    // consumed browser account intent
	Issuer  string                // exact verified provider issuer
	Subject string                // exact verified provider subject
	Status  CentralStatusEvidence // fresh resolved central account status
	Session CentralSession        // newly frozen session admission facts
	// NewUser and Artifacts are used only when explicit registration finds no
	// existing binding. Email conflict cannot turn them into account adoption.
	NewUser          *User                      // prepared new local account
	Artifacts        *AuthRegistrationArtifacts // current required registration artifacts
	Policy           CentralConsumerPolicy      // pinned consumer admission configuration
	RequestStartedAt time.Time                  // beginning of authority observation request
}

// CentralLoginCommit contains the committed account and immutable product session.
type CentralLoginCommit struct {
	User    *User          // current unchanged local account
	Session CentralSession // committed immutable session facts
	Created bool           // whether registration created this account
}

// CentralSessionStore owns transactional binding, session and status persistence.
type CentralSessionStore interface {
	// SaveLogin records an encrypted browser transaction with its original expiry.
	// Duplicate state digests fail instead of replacing another active flow.
	SaveLogin(context.Context, CentralLoginTransaction) error
	// ConsumeLogin claims the browser-bound state once before any provider exchange.
	// Expired or previously consumed state cannot be restored after later failure.
	ConsumeLogin(context.Context, string, string, time.Time) (CentralLoginTransaction, error)
	// RecordAccountStatus commits observations for a previously bound account
	// independently of later login success. Unknown local bindings are left absent.
	RecordAccountStatus(context.Context, CentralStatusEvidence) error
	// CompleteLogin atomically preserves local ownership, activates the sticky
	// human-auth fence and inserts the session after rechecking current evidence.
	CompleteLogin(context.Context, CentralLoginCompletion) (CentralLoginCommit, error)
	// ReadSession loads immutable issued facts before the authority status call.
	// This snapshot alone cannot authorize a request or override later logout.
	ReadSession(context.Context, string) (CentralSession, error)
	// PublishAndRead serializes monotone status publication and reloads the session
	// with current revocation and local account state before request admission.
	PublishAndRead(context.Context, string, CentralStatusEvidence) (CentralSession, CentralStatusEvidence, *User, error)
	// RevokeSession persists local logout before the browser cookie is removed.
	// Repeated revocation is harmless; storage failure remains an explicit error.
	RevokeSession(context.Context, string, time.Time) error
	// RevokeUserSessions invalidates local human sessions for the supplied owner.
	// It does not revoke product API keys or change financial resource ownership.
	RevokeUserSessions(context.Context, int64, time.Time) error
}

// CentralFlow coordinates provider proof, account ownership and durable browser sessions.
type CentralFlow struct {
	Options        CentralLoginOptions                                       // validated immutable deployment configuration
	Store          CentralSessionStore                                       // durable transactional session persistence
	Authority      CentralIdentityAuthority                                  // separately authenticated central authority
	Provider       OIDCOAuthClient                                           // verified provider exchange and claims
	Cipher         SecretEncryptor                                           // stable authenticated intent encryption
	Auth           *AuthService                                              // current local registration rules
	TOTP           *TotpService                                              // existing local factor verification
	SignupDefaults func(context.Context) (*AuthSourceDefaultSettings, error) // current third-party signup policy
	Now            func() time.Time                                          // injected authentication observation clock
}

// CentralBeginResult carries a public redirect and a browser-only transaction secret.
type CentralBeginResult struct {
	AuthorizationURL string    // validated provider authorization redirect
	BrowserSecret    string    // opaque transaction cookie value
	ExpiresAt        time.Time // transaction cookie expiration time
}

// CentralFinishResult carries the opaque cookie after its session commit succeeds.
type CentralFinishResult struct {
	Secret  string         // opaque product session cookie
	Session CentralSession // committed server session facts
}

// CentralAuthenticated contains one fresh request admission and its local owner.
type CentralAuthenticated struct {
	User             *User                 // fresh active local account
	Session          CentralSession        // immutable issued session evidence
	Status           CentralStatusEvidence // serialized current authority observation
	RequestStartedAt time.Time             // original status request start
}

// Begin creates a one-use encrypted OAuth transaction for an explicit intent.
// Provider hints come from the configured alias allowlist and cannot redirect
// credentials to browser-selected endpoints or substitute another issuer.
func (f *CentralFlow) Begin(ctx context.Context, intent, provider, invitation string, owner *CentralOwnerProof) (CentralBeginResult, error) {
	if intent != CentralIntentLogin && intent != CentralIntentRegister && intent != CentralIntentBind {
		return CentralBeginResult{}, ErrCentralEvidenceInvalid
	}
	if intent == CentralIntentBind && (f.Options.TestBindingProfile != CentralTestBindingProfile || owner == nil) {
		return CentralBeginResult{}, ErrCentralBindingDisabled
	}
	if intent != CentralIntentBind && owner != nil || len(invitation) > 256 {
		return CentralBeginResult{}, ErrCentralEvidenceInvalid
	}
	if provider != "" {
		allowed := false
		for _, alias := range f.Options.Providers {
			allowed = allowed || provider == alias
		}
		if !allowed {
			return CentralBeginResult{}, ErrCentralEvidenceInvalid
		}
	}
	state, err := RandomHexString(32)
	if err != nil {
		return CentralBeginResult{}, ErrCentralUnavailable
	}
	browser, err := RandomHexString(32)
	if err != nil {
		return CentralBeginResult{}, ErrCentralUnavailable
	}
	verifier, err := RandomHexString(32)
	if err != nil {
		return CentralBeginResult{}, ErrCentralUnavailable
	}
	nonce, err := RandomHexString(32)
	if err != nil {
		return CentralBeginResult{}, ErrCentralUnavailable
	}
	now := f.now()
	flow := CentralLoginIntent{Intent: intent, StateDigest: CentralSecretDigest(state), BrowserDigest: CentralSecretDigest(browser), Issuer: f.Options.OIDC.IssuerURL, ClientID: f.Options.OIDC.ClientID, AuthorityIncarnation: f.Options.Policy.AuthorityIncarnation, Nonce: nonce, Verifier: verifier, InvitationCode: invitation, OwnerProof: owner}
	plain, err := json.Marshal(flow)
	if err != nil {
		return CentralBeginResult{}, ErrCentralUnavailable
	}
	encrypted, err := f.Cipher.Encrypt(string(plain))
	if err != nil {
		return CentralBeginResult{}, ErrCentralUnavailable
	}
	transaction := CentralLoginTransaction{StateDigest: flow.StateDigest, BrowserDigest: flow.BrowserDigest, Ciphertext: encrypted, CreatedAt: now, ExpiresAt: now.Add(CentralAdmissionBudget)}
	if err := f.Store.SaveLogin(ctx, transaction); err != nil {
		return CentralBeginResult{}, err
	}
	authorize, err := url.Parse(f.Options.OIDC.AuthorizeURL)
	if err != nil {
		return CentralBeginResult{}, ErrCentralEvidenceInvalid
	}
	query := authorize.Query()
	query.Set("response_type", "code")
	query.Set("client_id", f.Options.OIDC.ClientID)
	query.Set("redirect_uri", f.Options.OIDC.RedirectURL)
	query.Set("scope", "openid email profile")
	query.Set("state", state)
	query.Set("nonce", nonce)
	challenge := sha256.Sum256([]byte(verifier))
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	query.Set("max_age", "28800")
	if provider != "" {
		query.Set("kc_idp_hint", provider)
	}
	if intent == CentralIntentBind {
		query.Set("max_age", "0")
		query.Set("prompt", "login")
	}
	authorize.RawQuery = query.Encode()
	return CentralBeginResult{AuthorizationURL: authorize.String(), BrowserSecret: browser, ExpiresAt: transaction.ExpiresAt}, nil
}

// Finish consumes browser state before exchanging the single-use provider code.
// A later failure requires a new browser flow. Fresh central evidence and local
// ownership commit together before the result exposes any product cookie value.
func (f *CentralFlow) Finish(ctx context.Context, state, browser, code string) (CentralFinishResult, error) {
	if !centralSecret(state) || !centralSecret(browser) || code == "" || len(code) > 8192 {
		return CentralFinishResult{}, ErrCentralSessionExpired
	}
	transaction, err := f.Store.ConsumeLogin(ctx, CentralSecretDigest(state), CentralSecretDigest(browser), f.now())
	if err != nil {
		return CentralFinishResult{}, err
	}
	plain, err := f.Cipher.Decrypt(transaction.Ciphertext)
	if err != nil {
		return CentralFinishResult{}, ErrCentralSessionExpired
	}
	var intent CentralLoginIntent
	if json.Unmarshal([]byte(plain), &intent) != nil || intent.StateDigest != transaction.StateDigest || intent.BrowserDigest != transaction.BrowserDigest ||
		intent.Issuer != f.Options.OIDC.IssuerURL || intent.ClientID != f.Options.OIDC.ClientID || intent.AuthorityIncarnation != f.Options.Policy.AuthorityIncarnation {
		return CentralFinishResult{}, ErrCentralSessionExpired
	}
	if intent.Intent == CentralIntentBind && f.Options.TestBindingProfile != CentralTestBindingProfile {
		return CentralFinishResult{}, ErrCentralBindingDisabled
	}
	token, err := f.Provider.ExchangeCode(ctx, f.Options.OIDC, code, f.Options.OIDC.RedirectURL, intent.Verifier)
	if err != nil || token == nil || !strings.EqualFold(token.TokenType, "Bearer") || token.AccessToken == "" || token.IDToken == "" || len(token.AccessToken) > 16384 || len(token.IDToken) > 16384 {
		return CentralFinishResult{}, ErrCentralSessionExpired
	}
	claims, err := f.Provider.ValidateIDToken(ctx, f.Options.OIDC, token.IDToken, intent.Nonce)
	if err != nil || claims == nil || claims.AuthenticatedAt == nil || !centralIdentifier(claims.Subject) || claims.Issuer != intent.Issuer {
		return CentralFinishResult{}, ErrCentralSessionExpired
	}
	info, err := f.Provider.FetchUserInfo(ctx, f.Options.OIDC, token)
	if err != nil || info == nil || info.Subject != claims.Subject {
		return CentralFinishResult{}, ErrCentralSessionExpired
	}
	started := f.now()
	resolved, err := f.Authority.ResolveSelf(ctx, token.AccessToken, transaction.StateDigest)
	if err != nil {
		return CentralFinishResult{}, err
	}
	now := f.now()
	if err := ValidateCentralStatus(f.Options.Policy, resolved.Status, started, now); err != nil {
		return CentralFinishResult{}, err
	}
	// Publish known-account fences before any later proof or registration failure.
	// Otherwise a rejected callback could roll back a newer observed revocation.
	if err := f.Store.RecordAccountStatus(ctx, resolved.Status); err != nil {
		return CentralFinishResult{}, err
	}
	if resolved.Admission.Profile == CentralProfileProviderSession && !resolved.Admission.AuthenticatedAt.Equal(*claims.AuthenticatedAt) {
		return CentralFinishResult{}, ErrCentralEvidenceInvalid
	}
	secret, err := RandomHexString(32)
	if err != nil {
		return CentralFinishResult{}, ErrCentralUnavailable
	}
	csrf, err := RandomHexString(32)
	if err != nil {
		return CentralFinishResult{}, ErrCentralUnavailable
	}
	expires := now.Add(CentralAdmissionBudget)
	if resolved.Admission.ValidUntil.Before(expires) {
		expires = resolved.Admission.ValidUntil
	}
	if claims.ExpiresAt.Before(expires) {
		expires = claims.ExpiresAt
	}
	session := CentralSession{Digest: CentralSecretDigest(secret), CSRFSecret: csrf, LocalUserID: 1, Account: resolved.Status.Account, SecurityEpoch: resolved.Status.SecurityEpoch, AttachmentGeneration: resolved.Status.AttachmentGeneration, Admission: resolved.Admission, CreatedAt: now, ExpiresAt: expires}
	if err := AuthorizeCentralSession(f.Options.Policy, session, resolved.Status, started, now, CentralAccessOrdinary); err != nil {
		return CentralFinishResult{}, err
	}
	completion := CentralLoginCompletion{Intent: intent, Issuer: claims.Issuer, Subject: claims.Subject, Status: resolved.Status, Session: session, Policy: f.Options.Policy, RequestStartedAt: started}
	var plan AuthSignupGrantPlan
	if intent.Intent == CentralIntentRegister {
		completion.NewUser, completion.Artifacts, plan, err = f.prepareRegistration(ctx, intent, claims, info, resolved.Status.Account)
		if err != nil {
			return CentralFinishResult{}, err
		}
	}
	committed, err := f.Store.CompleteLogin(ctx, completion)
	if err != nil {
		return CentralFinishResult{}, err
	}
	if committed.Created {
		f.Auth.AuthAssignSubscriptions(ctx, committed.User.ID, plan.Subscriptions, "auto assigned by central signup defaults")
		f.Auth.AuthBindRegistrationAffiliate(ctx, committed.User.ID, "")
	}
	return CentralFinishResult{Secret: secret, Session: committed.Session}, nil
}

// Authenticate publishes a fresh status observation before reloading the local
// session and account. Unavailable status, completed logout and changed issued
// counters reject the request without falling back to legacy authentication.
func (f *CentralFlow) Authenticate(ctx context.Context, secret string) (CentralAuthenticated, error) {
	if !centralSecret(secret) {
		return CentralAuthenticated{}, ErrCentralSessionExpired
	}
	digest := CentralSecretDigest(secret)
	issued, err := f.Store.ReadSession(ctx, digest)
	if err != nil {
		return CentralAuthenticated{}, err
	}
	if issued.RevokedAt != nil || !f.now().Add(CentralClockUncertainty).Before(issued.ExpiresAt) {
		return CentralAuthenticated{}, ErrCentralSessionExpired
	}
	started := f.now()
	observed, err := f.Authority.GetAccountStatus(ctx, issued.Account)
	if err != nil {
		return CentralAuthenticated{}, err
	}
	if err := ValidateCentralStatus(f.Options.Policy, observed, started, f.now()); err != nil {
		return CentralAuthenticated{}, err
	}
	session, status, user, err := f.Store.PublishAndRead(ctx, digest, observed)
	if err != nil {
		return CentralAuthenticated{}, err
	}
	if user == nil || !user.IsActive() || !user.CentralManaged {
		return CentralAuthenticated{}, ErrCentralAccountInactive
	}
	if err := AuthorizeCentralSession(f.Options.Policy, session, status, started, f.now(), CentralAccessOrdinary); err != nil {
		return CentralAuthenticated{}, err
	}
	return CentralAuthenticated{User: user, Session: session, Status: status, RequestStartedAt: started}, nil
}

// VerifyLegacyOwner admits only the explicit test migration candidate and
// requires a current password plus the already configured local TOTP factor.
// Credential state is checked again after proof and inside the binding commit.
func (f *CentralFlow) VerifyLegacyOwner(ctx context.Context, userID int64, password, code string) (*CentralOwnerProof, error) {
	if f.Options.TestBindingProfile != CentralTestBindingProfile || f.TOTP == nil {
		return nil, ErrCentralBindingDisabled
	}
	user, err := f.Auth.Users.GetByID(ctx, userID)
	if err != nil || !user.IsActive() || user.CentralManaged || !user.TotpEnabled || user.TotpEnabledAt == nil || !f.Auth.CheckPassword(password, user.PasswordHash) {
		return nil, ErrCentralProofRequired
	}
	fingerprint := CentralOwnerFingerprint(user)
	if err := f.TOTP.VerifyCode(ctx, userID, code); err != nil {
		return nil, ErrCentralProofRequired
	}
	fresh, err := f.Auth.Users.GetByID(ctx, userID)
	if err != nil || !fresh.IsActive() || fresh.CentralManaged || CentralOwnerFingerprint(fresh) != fingerprint {
		return nil, ErrCentralProofRequired
	}
	return &CentralOwnerProof{LocalUserID: userID, CredentialFingerprint: fingerprint, VerifiedAt: f.now()}, nil
}

// prepareRegistration applies existing creation rules without resolving ownership
// by email. A matching mailbox remains a conflict handled by the atomic store;
// only a separate admitted binding ceremony can adopt an existing local account.
func (f *CentralFlow) prepareRegistration(ctx context.Context, intent CentralLoginIntent, claims *OIDCVerifiedClaims, info *OIDCUserInfoClaims, account CentralAccountReference) (*User, *AuthRegistrationArtifacts, AuthSignupGrantPlan, error) {
	if f.Auth.Settings == nil || !f.Auth.Settings.IsRegistrationEnabled(ctx) {
		return nil, nil, AuthSignupGrantPlan{}, ErrRegDisabled
	}
	email := ""
	if info.EmailVerified != nil && *info.EmailVerified {
		email = strings.TrimSpace(info.Email)
	}
	if email == "" && claims.EmailVerified != nil && *claims.EmailVerified {
		email = strings.TrimSpace(claims.Email)
	}
	verifiedEmail := email != ""
	if email == "" {
		if f.SignupDefaults == nil {
			return nil, nil, AuthSignupGrantPlan{}, ErrCentralUnavailable
		}
		defaults, err := f.SignupDefaults(ctx)
		if err != nil || defaults != nil && defaults.ForceEmailOnThirdPartySignup {
			return nil, nil, AuthSignupGrantPlan{}, ErrCentralProofRequired
		}
		encoded, err := json.Marshal(account)
		if err != nil {
			return nil, nil, AuthSignupGrantPlan{}, ErrCentralUnavailable
		}
		email = OIDCSyntheticEmailFromIdentityKey(string(encoded))
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 255 {
		return nil, nil, AuthSignupGrantPlan{}, ErrCentralEvidenceInvalid
	}
	if verifiedEmail {
		if err := f.Auth.AuthValidateRegistrationEmailPolicy(ctx, email); err != nil {
			return nil, nil, AuthSignupGrantPlan{}, err
		}
	}
	artifacts, err := f.Auth.AuthResolveRegistrationArtifacts(ctx, intent.InvitationCode, ErrOAuthInvitationRequired)
	if err != nil {
		return nil, nil, AuthSignupGrantPlan{}, err
	}
	password, err := RandomHexString(32)
	if err != nil {
		return nil, nil, AuthSignupGrantPlan{}, ErrCentralUnavailable
	}
	hash, err := f.Auth.HashPassword(password)
	if err != nil {
		return nil, nil, AuthSignupGrantPlan{}, ErrCentralUnavailable
	}
	plan := f.Auth.AuthResolveSignupGrantPlan(ctx, "oidc")
	name := strings.TrimSpace(claims.PreferredUsername)
	if name == "" {
		name = OIDCFallbackUsername(claims.Subject)
	}
	if len([]rune(name)) > 100 {
		name = string([]rune(name)[:100])
	}
	user := &User{Email: email, Username: name, PasswordHash: hash, CentralManaged: true, Role: RoleUser, Status: StatusActive, Balance: plan.Balance, Concurrency: plan.Concurrency, RPMLimit: f.Auth.Settings.GetDefaultUserRPMLimit(ctx), SignupSource: "oidc"}
	return user, artifacts, plan, nil
}

// CentralOwnerFingerprint binds test migration proof to current credential state.
// Password reset, mailbox change, TOTP replacement or enrollment changes invalidate it.
func CentralOwnerFingerprint(user *User) string {
	data, err := json.Marshal(struct {
		Version int64
		Factor  *string
		Enabled bool
		Since   *time.Time
	}{ResolvedTokenVersion(user), user.TotpSecretEncrypted, user.TotpEnabled, user.TotpEnabledAt})
	if err != nil {
		return ""
	}
	return CentralSecretDigest(string(data))
}

// CentralSecretDigest creates the durable lookup value for an opaque browser secret.
// Raw cookie and transaction values remain outside persistence and diagnostic text.
func CentralSecretDigest(secret string) string {
	digest := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(digest[:])
}

// CentralCSRFMatches compares independent request proof with its authenticated session.
// The proof is useful only alongside the opaque HttpOnly product session cookie.
func CentralCSRFMatches(session CentralSession, supplied string) bool {
	return centralSecret(supplied) && subtle.ConstantTimeCompare([]byte(session.CSRFSecret), []byte(supplied)) == 1
}

// centralSecret admits only the fixed random representation produced for browser flows.
// It bounds cookie input before hashing or performing a persistence lookup.
func centralSecret(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// now returns the injected clock in UTC for persistent authentication observations.
// A missing clock uses wall time without extending stored evidence or deadlines.
func (f *CentralFlow) now() time.Time {
	if f.Now != nil {
		return f.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}
