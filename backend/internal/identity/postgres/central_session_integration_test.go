//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/stretchr/testify/require"

	dbent "github.com/TokenFlux/TokenRouter/ent"
	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/testutil/postgrescontainer"
)

// central_session_integration_test.go verifies browser authentication writes
// against the application's actual migrated PostgreSQL schema. The fixtures
// share the SQL pool with Ent so transaction participation, row locks and unique
// constraints execute through the same adapters used by the application. Each
// test owns an isolated database and uses a fixed microsecond-precision clock.
//
// These scenarios concentrate on ownership and revocation boundaries: a failed
// session write must roll back registration, concurrent registration must not
// split one authority account between local owners, a changed local credential
// must invalidate migration proof, and delayed ACTIVE evidence must not erase a
// committed denial. Ordinary unit tests cover the remaining pure policy cases.

// centralStoreFixture builds matching real database participants for one test.
func centralStoreFixture(t *testing.T) (*CentralSessionStore, *sql.DB, time.Time) {
	t.Helper()
	db := postgrescontainer.New(t)
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	users := NewUserStore(client, db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	state := NewAuthState(client, &identity.AuthDependencies{Users: users})
	return NewCentralSessionStore(db, client, state, func() time.Time { return now }), db, now
}

// centralCompletion creates independently issued evidence for one authority account.
func centralCompletion(now time.Time, account, email, secret string) identity.CentralLoginCompletion {
	policy := identity.CentralConsumerPolicy{ConsumerID: "gettok", AuthorityIncarnation: "authority-test", OrdinaryPolicyID: "gettok-ordinary-login", OrdinaryPolicyVersion: 1}
	status := identity.CentralStatusEvidence{Account: identity.CentralAccountReference{AccountID: account, AuthorityIncarnation: policy.AuthorityIncarnation}, ConsumerID: policy.ConsumerID, Eligibility: identity.CentralEligibilityActive, Revision: 1, SecurityEpoch: 1, AttachmentGeneration: 1, ObservedAt: now, ValidUntil: now.Add(identity.CentralSourceLease)}
	return identity.CentralLoginCompletion{
		Intent: identity.CentralLoginIntent{Intent: identity.CentralIntentRegister}, Issuer: "https://identity.test/realms/test", Subject: "subject-" + account,
		Status: status, Policy: policy, RequestStartedAt: now,
		NewUser: &identity.User{Email: email, PasswordHash: "unusable-fixture-hash", CentralManaged: true, Role: "user", Status: "active", Balance: 17, Concurrency: 2},
		Session: identity.CentralSession{Digest: identity.CentralSecretDigest(secret), CSRFSecret: strings.Repeat("c", 64), Account: status.Account, SecurityEpoch: 1, AttachmentGeneration: 1, CreatedAt: now, ExpiresAt: now.Add(4 * time.Minute), Admission: identity.CentralSessionAdmission{AuthoritySessionID: "qualified-session-" + account, Profile: identity.CentralProfileProviderSession, PolicyID: policy.OrdinaryPolicyID, PolicyVersion: 1, AuthenticatedAt: now.Add(-time.Minute), ValidUntil: now.Add(4 * time.Minute)}},
	}
}

// TestCentralStoreAtomicOwnership proves conditional login consumption,
// concurrent first ownership, and rollback after a later session-key conflict.
func TestCentralStoreAtomicOwnership(t *testing.T) {
	store, db, now := centralStoreFixture(t)
	ctx := t.Context()
	flow := identity.CentralLoginTransaction{StateDigest: identity.CentralSecretDigest("state"), BrowserDigest: identity.CentralSecretDigest("browser"), Ciphertext: "encrypted-intent", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	require.NoError(t, store.SaveLogin(ctx, flow))
	_, err := store.ConsumeLogin(ctx, flow.StateDigest, identity.CentralSecretDigest("wrong-browser"), now)
	require.ErrorIs(t, err, identity.ErrCentralSessionExpired)
	var consumed sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		consumed.Go(func() {
			_, err := store.ConsumeLogin(ctx, flow.StateDigest, flow.BrowserDigest, now)
			results <- err
		})
	}
	consumed.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, identity.ErrCentralSessionExpired)
		}
	}
	require.Equal(t, 1, successes)

	first := centralCompletion(now, "one", "first@example.invalid", "session-one")
	second := centralCompletion(now, "one", "second@example.invalid", "session-two")
	type result struct {
		commit identity.CentralLoginCommit // committed local owner and issued session
		err    error                       // database transaction result
	}
	commits := make(chan result, 2)
	for _, input := range []identity.CentralLoginCompletion{first, second} {
		consumed.Go(func() {
			commit, err := store.CompleteLogin(ctx, input)
			commits <- result{commit, err}
		})
	}
	consumed.Wait()
	close(commits)
	var userID int64
	created := 0
	for result := range commits {
		require.NoError(t, result.err)
		if result.commit.Created {
			created++
		}
		if userID != 0 {
			require.Equal(t, userID, result.commit.User.ID)
		}
		userID = result.commit.User.ID
		require.Equal(t, float64(17), result.commit.User.Balance)
		require.True(t, result.commit.User.CentralManaged)
	}
	require.Equal(t, 1, created)
	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&count))
	require.Equal(t, 1, count)
	// The duplicate digest fails after a different new user and binding were
	// written. Their absence proves registration joined the outer transaction.
	conflict := centralCompletion(now, "other", "rollback@example.invalid", "session-one")
	_, err = store.CompleteLogin(ctx, conflict)
	require.ErrorIs(t, err, identity.ErrCentralConflict)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM users WHERE email='rollback@example.invalid'").Scan(&count))
	require.Zero(t, count)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM central_identity_bindings WHERE account_id='other'").Scan(&count))
	require.Zero(t, count)
	var originalEmail string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT email FROM users WHERE id=$1", userID).Scan(&originalEmail))
	conflict = centralCompletion(now, "email-collision", originalEmail, "email-session")
	_, err = store.CompleteLogin(ctx, conflict)
	require.ErrorIs(t, err, identity.ErrCentralConflict)
}

// TestCentralStoreBindingAndRevocation fences old credentials at commit while
// preserving balances and machine keys, then retains newer denial and logout.
func TestCentralStoreBindingAndRevocation(t *testing.T) {
	store, db, now := centralStoreFixture(t)
	ctx := t.Context()
	user := &identity.User{Email: "owner@example.invalid", PasswordHash: "old-hash", Role: "user", Status: "active", Balance: 42, Concurrency: 3}
	require.NoError(t, store.auth.Users.Create(ctx, user))
	_, err := db.ExecContext(ctx, "UPDATE users SET totp_enabled=true,totp_secret_encrypted='sealed-factor',totp_enabled_at=$2 WHERE id=$1", user.ID, now.Add(-time.Hour))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO api_keys(user_id,key,name) VALUES($1,'machine-key-fixture','retained')", user.ID)
	require.NoError(t, err)
	owner, err := store.auth.Users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	input := centralCompletion(now, "bound", "unused@example.invalid", "bound-session")
	input.NewUser = nil
	input.Intent = identity.CentralLoginIntent{Intent: identity.CentralIntentBind, OwnerProof: &identity.CentralOwnerProof{LocalUserID: user.ID, CredentialFingerprint: identity.CentralOwnerFingerprint(owner), VerifiedAt: now}}
	_, err = db.ExecContext(ctx, "UPDATE users SET password_hash='replacement-hash' WHERE id=$1", user.ID)
	require.NoError(t, err)
	_, err = store.CompleteLogin(ctx, input)
	require.ErrorIs(t, err, identity.ErrCentralProofRequired)
	owner, err = store.auth.Users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.False(t, owner.CentralManaged)
	input.Intent.OwnerProof.CredentialFingerprint = identity.CentralOwnerFingerprint(owner)
	commit, err := store.CompleteLogin(ctx, input)
	require.NoError(t, err)
	require.False(t, commit.Created)
	require.Equal(t, user.ID, commit.User.ID)
	require.Equal(t, float64(42), commit.User.Balance)
	require.True(t, commit.User.CentralManaged)
	err = store.auth.AuthEnsureEmailOAuthIdentity(ctx, commit.User.ID, identity.EmailOAuthIdentityInput{ProviderType: "github", ProviderKey: "github", ProviderSubject: "delayed-legacy-subject", Email: commit.User.Email, EmailVerified: true})
	require.ErrorIs(t, err, identity.ErrCentralLoginRequired)
	var legacyBindings int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM auth_identities WHERE user_id=$1 AND provider_subject='delayed-legacy-subject'", commit.User.ID).Scan(&legacyBindings))
	require.Zero(t, legacyBindings)
	legacy := identity.NewSessionService(identity.SessionOptions{Secret: "test-secret", ExpireHour: 1}, store.auth.Users, nil, nil, nil)
	_, err = legacy.GenerateToken(ctx, commit.User)
	require.ErrorIs(t, err, identity.ErrCentralLoginRequired)

	denied := input.Status
	denied.Revision, denied.SecurityEpoch, denied.Eligibility = 2, 2, identity.CentralEligibilitySuspended
	require.NoError(t, store.RecordAccountStatus(ctx, denied))
	session, status, _, err := store.PublishAndRead(ctx, commit.Session.Digest, input.Status)
	require.NoError(t, err)
	require.Equal(t, denied, status)
	require.Equal(t, uint64(1), session.SecurityEpoch)
	require.Error(t, identity.AuthorizeCentralSession(input.Policy, session, status, now, now, identity.CentralAccessOrdinary))
	require.NoError(t, store.RevokeSession(ctx, commit.Session.Digest, now))
	require.NoError(t, store.RevokeSession(ctx, commit.Session.Digest, now.Add(time.Second)))
	session, err = store.ReadSession(ctx, commit.Session.Digest)
	require.NoError(t, err)
	require.Equal(t, &now, session.RevokedAt)
	require.Equal(t, commit.Session.Admission, session.Admission)
	var keys int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM api_keys WHERE user_id=$1", user.ID).Scan(&keys))
	require.Equal(t, 1, keys)
	_, err = db.ExecContext(ctx, "DELETE FROM central_identity_sessions WHERE local_user_id=$1", user.ID)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "DELETE FROM central_identity_bindings WHERE local_user_id=$1", user.ID)
	require.NoError(t, err)
	owner, err = store.auth.Users.GetByID(context.Background(), user.ID)
	require.NoError(t, err)
	require.True(t, owner.CentralManaged, "missing binding must not silently restore legacy human authentication")
}
