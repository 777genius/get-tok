//go:build integration

package postgrescontainer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	postgresinfra "github.com/TokenFlux/TokenRouter/internal/infra/postgres"
	"github.com/TokenFlux/TokenRouter/migrations"
)

// postgres.go creates isolated PostgreSQL fixtures and applies application
// migrations before domain records are read or written. The ordinary profile
// starts a dedicated container. An explicitly supplied loopback TEST server can
// instead host a randomly named temporary database; the supplied administrator
// database is never migrated or dropped. Both paths exercise the same embedded
// production migrations and return a SQL pool owned by the calling test.
//
// Cleanup runs after dependent test participants have stopped. The SQL pool
// closes before its container terminates or its temporary database is removed.
// Native mode is useful for verified PostgreSQL runtimes on executors without
// Docker, and remains distinct from changing the configured container image.
// Native connection options cannot redirect either pool away from the validated
// loopback target, and startup handshakes have their own bounded timeout.

const (
	// nativeConnectTimeoutSeconds caps PostgreSQL connection establishment before
	// operation contexts can govern migrations or the eventual database cleanup.
	nativeConnectTimeoutSeconds = 5
)

// New returns a pool for a dedicated migrated PostgreSQL fixture or fails the
// calling test. An explicit TOKENROUTER_TEST_POSTGRES_DSN selects native mode.
// Container startup, connection-string discovery, and migrations
// share a two-minute context; TOKENROUTER_TEST_POSTGRES_IMAGE can replace the
// default image. Cleanup closes the pool before terminating any created
// container with a fresh thirty-second context, including after startup errors.
func New(t *testing.T) *sql.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if dsn := strings.TrimSpace(os.Getenv("TOKENROUTER_TEST_POSTGRES_DSN")); dsn != "" {
		return newNative(t, ctx, dsn)
	}
	image := strings.TrimSpace(os.Getenv("TOKENROUTER_TEST_POSTGRES_IMAGE"))
	if image == "" {
		image = "postgres:18.1-alpine3.23"
	}
	container, err := tcpostgres.Run(ctx, image,
		tcpostgres.WithDatabase("storage_contracts"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.BasicWaitStrategies())
	// Register any created container before startup errors can stop this test.
	// Later client cleanups run first because testing reverses registration order.
	if container != nil {
		t.Cleanup(func() {
			// Setup or test cancellation must not cancel Docker removal. Start the
			// bounded cleanup context when this callback runs.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := container.Terminate(cleanupCtx); err != nil {
				t.Errorf("terminate PostgreSQL container: %v", err)
			}
		})
	}
	require.NoError(t, err)
	dsn, err := container.ConnectionString(ctx, "sslmode=disable", "TimeZone=UTC")
	require.NoError(t, err)
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, postgresinfra.ApplyMigrations(ctx, db, migrations.FS))
	return db
}

// newNative creates an isolated database on an explicitly supplied local test
// server. It rejects non-loopback hosts and administrator database names without
// the test suffix, never migrates the administrator database, and removes only
// its own random database after closing the test pool. This supports native
// PostgreSQL runners while retaining the same embedded migrations as Docker.
func newNative(t *testing.T, ctx context.Context, dsn string) *sql.DB {
	t.Helper()
	u, err := nativeTestURL(dsn)
	require.NoError(t, err)
	admin, err := sql.Open("postgres", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	var random [12]byte
	_, err = rand.Read(random[:])
	require.NoError(t, err)
	name := "gettok_verification_" + hex.EncodeToString(random[:])
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+pq.QuoteIdentifier(name)+" TEMPLATE template0")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, err := admin.ExecContext(cleanup, "DROP DATABASE "+pq.QuoteIdentifier(name)+" WITH (FORCE)")
		require.NoError(t, err)
	})
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, postgresinfra.ApplyMigrations(ctx, db, migrations.FS))
	return db
}

// nativeTestURL validates the complete connection target before any pool is
// opened. Only ordinary TLS and session startup options are accepted because
// lib/pq appends query keys to its connection string without escaping the keys.
// The allowlist prevents both explicit target overrides and injected connection
// options from replacing the generated scratch database. A missing or nonpositive
// startup timeout selects five seconds; larger values are capped, while malformed
// and repeated timeout values are rejected before opening either connection.
func nativeTestURL(dsn string) (*url.URL, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, errors.New("native fixture requires a PostgreSQL URL")
	}
	if host := u.Hostname(); host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return nil, errors.New("native fixture requires a loopback PostgreSQL host")
	}
	if !strings.HasSuffix(strings.TrimPrefix(u.Path, "/"), "_test") {
		return nil, errors.New("native fixture requires a dedicated *_test administrator database")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("native fixture requires valid connection query options")
	}
	for option := range query {
		switch option {
		case "sslmode", "sslcert", "sslkey", "sslrootcert", "sslinline", "sslsni", "application_name", "fallback_application_name", "client_encoding", "timezone", "TimeZone", "connect_timeout":
		default:
			return nil, errors.New("native fixture does not support this connection query option")
		}
	}
	timeout := nativeConnectTimeoutSeconds
	if supplied, ok := query["connect_timeout"]; ok {
		if len(supplied) != 1 {
			return nil, errors.New("native fixture requires one connection timeout")
		}
		parsed, err := strconv.Atoi(supplied[0])
		if err != nil {
			return nil, errors.New("native fixture requires an integer connection timeout")
		}
		if parsed > 0 {
			timeout = min(parsed, nativeConnectTimeoutSeconds)
		}
	}
	// Normalize once before either pool opens. Replacing only the database path
	// later preserves this bounded startup policy for the scratch connection too.
	query.Set("connect_timeout", strconv.Itoa(timeout))
	u.RawQuery = query.Encode()
	return u, nil
}
