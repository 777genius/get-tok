package postgres

import (
	"testing"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/ent/authidentity"
	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// auth_state_test.go exercises legacy provider binding with the existing
// SQLite fixture. Successful binding remains available for an unmanaged
// account, while changing its durable ownership marker prevents a subsequent
// provider write. PostgreSQL qualification remains separate; this SQLite
// scenario establishes neither row-lock behavior nor concurrent activation.

// TestAuthEnsureEmailOAuthIdentityPreservesSQLiteOwnershipGuard verifies real
// provider persistence before and after central ownership activation. The
// second call must reject the changed account and retain only its original row.
func TestAuthEnsureEmailOAuthIdentityPreservesSQLiteOwnershipGuard(t *testing.T) {
	users, client := newUserEntRepo(t)
	ctx := t.Context()
	user := &identity.User{Email: "legacy-owner@example.invalid", PasswordHash: "fixture-password", Role: "user", Status: "active", Concurrency: 1}
	require.NoError(t, users.Create(ctx, user))
	state := NewAuthState(client, &identity.AuthDependencies{Users: users})
	input := identity.EmailOAuthIdentityInput{ProviderType: "github", ProviderKey: "github", ProviderSubject: "original-provider-subject", Email: user.Email, EmailVerified: true}
	require.NoError(t, state.AuthEnsureEmailOAuthIdentity(ctx, user.ID, input))
	// The sticky marker is immutable through ordinary Ent account updates;
	// this fixture applies the same explicit ownership transition as storage.
	var changed entsql.Result
	require.NoError(t, client.Driver().Exec(ctx, "UPDATE users SET central_managed = true WHERE id = $1", []any{user.ID}, &changed))
	affected, err := changed.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, affected)
	input.ProviderSubject = "delayed-provider-subject"
	require.ErrorIs(t, state.AuthEnsureEmailOAuthIdentity(ctx, user.ID, input), identity.ErrCentralLoginRequired)
	rows, err := client.AuthIdentity.Query().Where(authidentity.UserIDEQ(user.ID), authidentity.ProviderKeyEQ("github")).All(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "original-provider-subject", rows[0].ProviderSubject)
	require.Equal(t, user.ID, rows[0].UserID)
}
