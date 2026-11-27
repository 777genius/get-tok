package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"

	dbent "github.com/TokenFlux/TokenRouter/ent"
	dbuser "github.com/TokenFlux/TokenRouter/ent/user"
	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// central_session.go persists central browser transactions, account bindings and
// product sessions with PostgreSQL transactions. Account binding retains the
// original local user identifier and activates a separate sticky authentication
// fence. An email conflict cannot select an existing owner, and a previously
// bound account cannot move to another user through a later login request.
//
// First binding and standalone status publication acquire the same account
// lock before the binding row lock, retaining observations while ownership is
// being committed. Session reads follow publication under that transaction, so
// a completed local logout remains authoritative. Session evidence contains
// original counters and proof bounds; only the revocation column changes later.
// Login state is consumed by
// one conditional update before provider exchange, and failure after consumption
// requires a new browser transaction instead of restoring an old authorization.

// CentralSessionStore persists central identities beside the existing local account store.
type CentralSessionStore struct {
	db     *sql.DB          // shared application database pool
	client *dbent.Client    // shared entity transaction client
	auth   *AuthState       // transaction-aware local account creation
	now    func() time.Time // current persistence observation clock
}

// NewCentralSessionStore retains matching SQL and Ent clients for atomic
// account and session writes. Authentication state must share those
// participants; a nil clock selects wall time for subsequent persistence
// observations.
func NewCentralSessionStore(db *sql.DB, client *dbent.Client, auth *AuthState, now func() time.Time) *CentralSessionStore {
	if now == nil {
		now = time.Now
	}
	return &CentralSessionStore{db: db, client: client, auth: auth, now: now}
}

// SaveLogin stores a bounded encrypted browser intent without retaining
// plaintext PKCE or nonce values in lookup columns. A duplicate state is an
// error rather than replacement of an earlier flow. The same statement removes
// at most one hundred long-expired intents and sessions, skipping rows held by
// other transactions. Cleanup uses separate retention windows and never
// removes bindings or the sticky user fence; an expired record cannot regain
// admission while awaiting later cleanup.
func (s *CentralSessionStore) SaveLogin(ctx context.Context, flow identity.CentralLoginTransaction) error {
	_, err := s.db.ExecContext(ctx, `WITH expired_intents AS (
 DELETE FROM central_identity_login_transactions WHERE state_hash IN (
  SELECT state_hash FROM central_identity_login_transactions
  WHERE expires_at < $4::timestamptz - interval '1 hour'
  ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED
 )
), expired_sessions AS (
 DELETE FROM central_identity_sessions WHERE token_hash IN (
  SELECT token_hash FROM central_identity_sessions
  WHERE expires_at < $4::timestamptz - interval '24 hours'
  ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED
 )
)
INSERT INTO central_identity_login_transactions
 (state_hash,browser_hash,encrypted_intent,created_at,expires_at) VALUES ($1,$2,$3,$4,$5)`,
		flow.StateDigest, flow.BrowserDigest, flow.Ciphertext, flow.CreatedAt, flow.ExpiresAt)
	return centralStoreError(err)
}

// ConsumeLogin atomically claims only the original browser's unused, unexpired
// transaction. The committed update precedes provider exchange, so a later
// failure cannot restore consumed state or replay the same authorization
// response.
func (s *CentralSessionStore) ConsumeLogin(ctx context.Context, state, browser string, now time.Time) (identity.CentralLoginTransaction, error) {
	flow := identity.CentralLoginTransaction{StateDigest: state, BrowserDigest: browser}
	err := s.db.QueryRowContext(ctx, `UPDATE central_identity_login_transactions SET consumed_at=$3
 WHERE state_hash=$1 AND browser_hash=$2 AND consumed_at IS NULL AND expires_at>$3 AND created_at<=$3
 RETURNING encrypted_intent,created_at,expires_at`, state, browser, now).Scan(&flow.Ciphertext, &flow.CreatedAt, &flow.ExpiresAt)
	return flow, centralStoreError(err)
}

// HasBinding checks the exact authority and verified provider identity before
// registration prepares new-account artifacts. An absent account returns false,
// while a different issuer or subject remains an ownership conflict. This read
// does not authorize a session: CompleteLogin repeats the binding decision under
// its transaction lock, so deletion or replacement after this read fails closed.
func (s *CentralSessionStore) HasBinding(ctx context.Context, account identity.CentralAccountReference, issuer, subject string) (bool, error) {
	var storedIssuer, storedSubject string
	err := s.db.QueryRowContext(ctx, `SELECT issuer,subject FROM central_identity_bindings
 WHERE authority_incarnation=$1 AND account_id=$2`, account.AuthorityIncarnation, account.AccountID).Scan(&storedIssuer, &storedSubject)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, centralStoreError(err)
	}
	if storedIssuer != issuer || storedSubject != subject {
		return false, identity.ErrCentralConflict
	}
	return true, nil
}

// CompleteLogin commits local ownership and the issued session in one transaction.
// The account-reference lock serializes first binding with standalone status
// publication; row and uniqueness constraints separately protect prior local
// ownership and provider identity.
//
// Existing bindings retain their user ID and never receive signup grants again.
// Test migration rechecks current password and factor state under the user lock.
// Registration participates in this transaction so invitation use, initial
// account funding, the central fence and session succeed or roll back together.
func (s *CentralSessionStore) CompleteLogin(ctx context.Context, input identity.CentralLoginCompletion) (identity.CentralLoginCommit, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return identity.CentralLoginCommit{}, identity.ErrCentralUnavailable
	}
	// Rollback retains ownership of every local write until the final commit.
	// Provider authentication already completed, but no browser credential is released here.
	defer func() { _ = tx.Rollback() }()
	ctx = dbent.NewTxContext(ctx, tx)
	client := tx.Client()
	if err := centralLockAccount(ctx, client, input.Status.Account); err != nil {
		return identity.CentralLoginCommit{}, err
	}
	var userID int64
	var issuer, subject string
	var storedJSON []byte
	err = centralScan(ctx, client, `SELECT local_user_id,issuer,subject,status_evidence FROM central_identity_bindings
 WHERE authority_incarnation=$1 AND account_id=$2 FOR UPDATE`, []any{input.Status.Account.AuthorityIncarnation, input.Status.Account.AccountID}, &userID, &issuer, &subject, &storedJSON)
	created := false
	status := input.Status
	if errors.Is(err, sql.ErrNoRows) {
		switch input.Intent.Intent {
		case identity.CentralIntentLogin:
			return identity.CentralLoginCommit{}, identity.ErrCentralNotBound
		case identity.CentralIntentRegister:
			if input.NewUser == nil || !input.NewUser.CentralManaged || input.NewUser.ID != 0 {
				return identity.CentralLoginCommit{}, identity.ErrCentralEvidenceInvalid
			}
			if err := s.auth.AuthCreateRegisteredUser(ctx, input.NewUser, input.Artifacts); err != nil {
				if errors.Is(err, identity.ErrEmailExists) {
					return identity.CentralLoginCommit{}, identity.ErrCentralConflict
				}
				return identity.CentralLoginCommit{}, err
			}
			userID, created = input.NewUser.ID, true
		case identity.CentralIntentBind:
			proof := input.Intent.OwnerProof
			now := s.now().UTC()
			if proof == nil || proof.LocalUserID <= 0 || proof.VerifiedAt.IsZero() || proof.VerifiedAt.After(now) || !now.Before(proof.VerifiedAt.Add(identity.CentralAdmissionBudget)) {
				return identity.CentralLoginCommit{}, identity.ErrCentralProofRequired
			}
			user, err := client.User.Query().Where(dbuser.IDEQ(proof.LocalUserID)).ForUpdate().Only(ctx)
			if err != nil {
				return identity.CentralLoginCommit{}, centralStoreError(err)
			}
			// Waiting for the user lock can consume the remaining proof lifetime.
			// Recheck the same proof before activating its permanent ownership fence.
			now = s.now().UTC()
			if proof.VerifiedAt.After(now) || !now.Before(proof.VerifiedAt.Add(identity.CentralAdmissionBudget)) {
				return identity.CentralLoginCommit{}, identity.ErrCentralProofRequired
			}
			current := UserFromEntity(user)
			if !current.IsActive() || current.CentralManaged || !current.TotpEnabled || current.TotpEnabledAt == nil || current.TotpEnabledAt.IsZero() || current.TotpEnabledAt.After(proof.VerifiedAt) || identity.CentralOwnerFingerprint(current) != proof.CredentialFingerprint {
				return identity.CentralLoginCommit{}, identity.ErrCentralProofRequired
			}
			// Activate the permanent human-authentication fence in the same commit as
			// the binding. Generic profile updates cannot clear this immutable field.
			if _, err := client.ExecContext(ctx, `UPDATE users SET central_managed=true WHERE id=$1 AND central_managed=false`, user.ID); err != nil {
				return identity.CentralLoginCommit{}, identity.ErrCentralUnavailable
			}
			userID = user.ID
		default:
			return identity.CentralLoginCommit{}, identity.ErrCentralEvidenceInvalid
		}
		statusJSON, err := json.Marshal(status)
		if err != nil {
			return identity.CentralLoginCommit{}, identity.ErrCentralEvidenceInvalid
		}
		if _, err := client.ExecContext(ctx, `INSERT INTO central_identity_bindings
 (local_user_id,authority_incarnation,account_id,issuer,subject,status_evidence) VALUES ($1,$2,$3,$4,$5,$6)`, userID, status.Account.AuthorityIncarnation, status.Account.AccountID, input.Issuer, input.Subject, statusJSON); err != nil {
			return identity.CentralLoginCommit{}, centralStoreError(err)
		}
	} else if err != nil {
		return identity.CentralLoginCommit{}, centralStoreError(err)
	} else {
		if issuer != input.Issuer || subject != input.Subject || input.Intent.Intent == identity.CentralIntentBind && (input.Intent.OwnerProof == nil || input.Intent.OwnerProof.LocalUserID != userID) {
			return identity.CentralLoginCommit{}, identity.ErrCentralConflict
		}
		var current identity.CentralStatusEvidence
		if json.Unmarshal(storedJSON, &current) != nil {
			return identity.CentralLoginCommit{}, identity.ErrCentralEvidenceInvalid
		}
		status, err = identity.MergeCentralStatus(current, input.Status)
		if err != nil {
			return identity.CentralLoginCommit{}, err
		}
		if err := centralPublish(ctx, client, userID, status); err != nil {
			return identity.CentralLoginCommit{}, err
		}
	}
	userEntity, err := client.User.Query().Where(dbuser.IDEQ(userID)).ForUpdate().Only(ctx)
	if err != nil {
		return identity.CentralLoginCommit{}, centralStoreError(err)
	}
	user := UserFromEntity(userEntity)
	if !user.IsActive() || !user.CentralManaged {
		return identity.CentralLoginCommit{}, identity.ErrCentralAccountInactive
	}
	session := input.Session
	session.LocalUserID = userID
	if err := identity.AuthorizeCentralSession(input.Policy, session, status, input.RequestStartedAt, s.now().UTC(), identity.CentralAccessOrdinary); err != nil {
		return identity.CentralLoginCommit{}, err
	}
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return identity.CentralLoginCommit{}, identity.ErrCentralEvidenceInvalid
	}
	if _, err := client.ExecContext(ctx, `INSERT INTO central_identity_sessions
 (token_hash,local_user_id,session_evidence,created_at,expires_at) VALUES ($1,$2,$3,$4,$5)`, session.Digest, userID, sessionJSON, session.CreatedAt, session.ExpiresAt); err != nil {
		return identity.CentralLoginCommit{}, centralStoreError(err)
	}
	if err := tx.Commit(); err != nil {
		return identity.CentralLoginCommit{}, identity.ErrCentralUnavailable
	}
	return identity.CentralLoginCommit{User: user, Session: session, Created: created}, nil
}

// ReadSession loads original issued evidence together with the independent
// local revocation column. Callers must publish fresh authority status and
// reload current state before treating this preliminary snapshot as request
// admission.
func (s *CentralSessionStore) ReadSession(ctx context.Context, digest string) (identity.CentralSession, error) {
	return centralReadSession(ctx, s.db, digest, false)
}

// RecordAccountStatus publishes an observation for an already bound account in
// its own transaction. The shared account lock waits for any first binding to
// commit before the binding row is read and locked. Revisions and counters then
// merge without allowing a delayed callback to overwrite a newer denial.
// Accounts still unbound after that wait acquire no ownership through a read.
// Successful publication commits before later proof or registration checks;
// rejection in those independent steps therefore cannot roll back a security
// fence that this process has already observed.
func (s *CentralSessionStore) RecordAccountStatus(ctx context.Context, incoming identity.CentralStatusEvidence) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return identity.ErrCentralUnavailable
	}
	// Rollback handles failed publication. A successful observation commits before
	// the independent login transaction can encounter another local-account error.
	defer func() { _ = tx.Rollback() }()
	client := tx.Client()
	if err := centralLockAccount(ctx, client, incoming.Account); err != nil {
		return err
	}
	var userID int64
	var encoded []byte
	err = centralScan(ctx, client, `SELECT local_user_id,status_evidence FROM central_identity_bindings
 WHERE authority_incarnation=$1 AND account_id=$2 FOR UPDATE`, []any{incoming.Account.AuthorityIncarnation, incoming.Account.AccountID}, &userID, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return centralStoreError(err)
	}
	var current identity.CentralStatusEvidence
	if json.Unmarshal(encoded, &current) != nil {
		return identity.ErrCentralEvidenceInvalid
	}
	merged, err := identity.MergeCentralStatus(current, incoming)
	if err != nil {
		return err
	}
	if err := centralPublish(ctx, client, userID, merged); err != nil {
		return err
	}
	return centralStoreError(tx.Commit())
}

// PublishAndRead merges current authority status under the binding lock before
// reloading the original session and local account. Binding-before-session
// lock order is shared with other publication paths, while logout never
// acquires a binding lock after a session lock. The transaction commits the
// observation even when concurrent cleanup or a logical session mismatch
// prevents admission. Callers then evaluate the returned original proof
// against those current facts, including any local revocation that completed
// during the authority request.
func (s *CentralSessionStore) PublishAndRead(ctx context.Context, digest string, incoming identity.CentralStatusEvidence) (identity.CentralSession, identity.CentralStatusEvidence, *identity.User, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return identity.CentralSession{}, identity.CentralStatusEvidence{}, nil, identity.ErrCentralUnavailable
	}
	// Failed publication rolls back. Successful publication commits even when a
	// later logical session rejection prevents admission, retaining the new fence.
	defer func() { _ = tx.Rollback() }()
	client := tx.Client()
	var userID int64
	var encoded []byte
	err = centralScan(ctx, client, `SELECT local_user_id,status_evidence FROM central_identity_bindings
 WHERE authority_incarnation=$1 AND account_id=$2 FOR UPDATE`, []any{incoming.Account.AuthorityIncarnation, incoming.Account.AccountID}, &userID, &encoded)
	if err != nil {
		return identity.CentralSession{}, identity.CentralStatusEvidence{}, nil, centralStoreError(err)
	}
	var current identity.CentralStatusEvidence
	if json.Unmarshal(encoded, &current) != nil {
		return identity.CentralSession{}, identity.CentralStatusEvidence{}, nil, identity.ErrCentralEvidenceInvalid
	}
	merged, err := identity.MergeCentralStatus(current, incoming)
	if err != nil {
		return identity.CentralSession{}, identity.CentralStatusEvidence{}, nil, err
	}
	if err := centralPublish(ctx, client, userID, merged); err != nil {
		return identity.CentralSession{}, identity.CentralStatusEvidence{}, nil, err
	}
	session, sessionErr := centralReadSession(ctx, client, digest, true)
	if sessionErr == nil && (session.LocalUserID != userID || session.Account != incoming.Account) {
		sessionErr = identity.ErrCentralEvidenceInvalid
	}
	var userEntity *dbent.User
	if sessionErr == nil {
		userEntity, err = client.User.Get(ctx, userID)
		if err != nil {
			sessionErr = centralStoreError(err)
		}
	}
	// Preserve the observation even when concurrent cleanup removed this session
	// or the local account became ineligible. Authentication still returns its error.
	if err := tx.Commit(); err != nil {
		return identity.CentralSession{}, identity.CentralStatusEvidence{}, nil, identity.ErrCentralUnavailable
	}
	if sessionErr != nil {
		return identity.CentralSession{}, identity.CentralStatusEvidence{}, nil, sessionErr
	}
	return session, merged, UserFromEntity(userEntity), nil
}

// RevokeSession commits the first logout timestamp before logout reports success.
// Missing and already revoked sessions are successful idempotent outcomes. The
// browser cookie remains inert until its existing expiration time.
func (s *CentralSessionStore) RevokeSession(ctx context.Context, digest string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE central_identity_sessions SET revoked_at=COALESCE(revoked_at,$2) WHERE token_hash=$1`, digest, now)
	return centralStoreError(err)
}

// RevokeUserSessions persists logout for existing local human sessions owned
// by the selected user. Machine credentials, future logins and central
// lifecycle remain separate; repeated withdrawal preserves each session's
// first revocation timestamp.
func (s *CentralSessionStore) RevokeUserSessions(ctx context.Context, userID int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE central_identity_sessions SET revoked_at=COALESCE(revoked_at,$2) WHERE local_user_id=$1`, userID, now)
	return centralStoreError(err)
}

// centralLockAccount serializes first ownership and standalone status publication.
// Both callers acquire this transaction-scoped lock before any binding row lock,
// using the same encoded authority account and namespace seed. Request cancellation
// bounds a blocked query, and transaction completion releases the lock. Existing
// session publication takes only binding and session row locks, so it introduces
// no reverse dependency on this account lock.
func centralLockAccount(ctx context.Context, query SQLExecutor, account identity.CentralAccountReference) error {
	lockKey, err := json.Marshal(account)
	if err != nil {
		return identity.ErrCentralEvidenceInvalid
	}
	if _, err := query.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,418731))`, string(lockKey)); err != nil {
		return identity.ErrCentralUnavailable
	}
	return nil
}

// centralReadSession checks lookup identity and timestamp columns against the
// encoded original session before returning it. Callers request a row lock
// when this read participates in status publication, preventing a completed
// concurrent logout from being hidden by an earlier snapshot. The independent
// revocation column overrides only local withdrawal state; it never rewrites
// proof deadlines or issued counters. Inconsistent encoded evidence fails
// closed, and missing rows retain the session-expired error category.
func centralReadSession(ctx context.Context, query SQLExecutor, digest string, locked bool) (identity.CentralSession, error) {
	statement := `SELECT local_user_id,session_evidence,created_at,expires_at,revoked_at FROM central_identity_sessions WHERE token_hash=$1`
	if locked {
		statement += ` FOR UPDATE`
	}
	var userID int64
	var data []byte
	var created, expires time.Time
	var revoked sql.NullTime
	if err := centralScan(ctx, query, statement, []any{digest}, &userID, &data, &created, &expires, &revoked); err != nil {
		return identity.CentralSession{}, centralStoreError(err)
	}
	var session identity.CentralSession
	if json.Unmarshal(data, &session) != nil || session.Digest != digest || session.LocalUserID != userID || !session.CreatedAt.Equal(created) || !session.ExpiresAt.Equal(expires) {
		return identity.CentralSession{}, identity.ErrCentralEvidenceInvalid
	}
	if revoked.Valid {
		value := revoked.Time.UTC()
		session.RevokedAt = &value
	}
	return session, nil
}

// centralPublish writes one already merged authority observation in the
// supplied transaction. The caller owns the binding lock and commit; this
// write never changes local ownership or previously issued session evidence.
func centralPublish(ctx context.Context, query SQLExecutor, userID int64, status identity.CentralStatusEvidence) error {
	encoded, err := json.Marshal(status)
	if err != nil {
		return identity.ErrCentralEvidenceInvalid
	}
	_, err = query.ExecContext(ctx, `UPDATE central_identity_bindings SET status_evidence=$2,updated_at=now() WHERE local_user_id=$1`, userID, encoded)
	return centralStoreError(err)
}

// centralScan consumes exactly one row through the supplied transaction-aware
// executor. It closes rows before another statement runs, preserves query and
// scan errors, and rejects unexpected additional records instead of selecting
// one silently.
func centralScan(ctx context.Context, query SQLExecutor, statement string, arguments []any, values ...any) error {
	rows, err := query.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return sql.ErrNoRows
	}
	if err := rows.Scan(values...); err != nil {
		return err
	}
	if rows.Next() {
		return identity.ErrCentralEvidenceInvalid
	}
	return rows.Err()
}

// centralStoreError hides database diagnostics while preserving missing-
// session, uniqueness-conflict and invalid-evidence categories. Any
// unrecognized persistence failure remains unavailable authentication state
// and cannot authorize a fallback to old credentials.
func centralStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) || dbent.IsNotFound(err) {
		return identity.ErrCentralSessionExpired
	}
	if errors.Is(err, identity.ErrCentralEvidenceInvalid) {
		return err
	}
	var constraint *pq.Error
	if errors.As(err, &constraint) && constraint.Code == "23505" {
		return identity.ErrCentralConflict
	}
	return identity.ErrCentralUnavailable
}
