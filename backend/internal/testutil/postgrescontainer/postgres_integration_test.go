//go:build integration

package postgrescontainer

import (
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// postgres_integration_test.go checks the native fixture's complete DSN before
// any connection pool can open. The tests exercise lib/pq's real URL conversion
// after validation, so generated database paths and bounded startup options
// cannot be displaced by query parameters.

// TestNativeTestURLRejectsTargetOverrides supplies URLs that look local before
// lib/pq converts their query parameters. Every target override or encoded key
// injection must fail before database creation or migrations can be attempted.
func TestNativeTestURLRejectsTargetOverrides(t *testing.T) {
	for _, query := range []string{
		"dbname=production",
		"host=database.example.invalid",
		"port=6543",
		"hostaddr=203.0.113.1",
		"service=production",
		"db%6Eame=production",
		"sslmode%3Ddisable%20dbname=production",
		"sslmode=disable;dbname=production",
		"sslmode=%zz",
	} {
		t.Run(query, func(t *testing.T) {
			u, err := nativeTestURL("postgres://fixture@127.0.0.1:5432/identity_test?" + query)
			require.Error(t, err)
			require.Nil(t, u)
		})
	}
	for _, dsn := range []string{
		"mysql://127.0.0.1/identity_test",
		"postgres://database.example.invalid/identity_test",
		"postgres://127.0.0.1/production",
	} {
		_, err := nativeTestURL(dsn)
		require.Error(t, err)
	}
}

// TestNativeTestURLPreservesScratchTargetAndBoundsStartup carries ordinary
// connection options through both pool URLs. lib/pq must receive exactly the
// selected database, with a positive timeout no greater than five seconds.
func TestNativeTestURLPreservesScratchTargetAndBoundsStartup(t *testing.T) {
	for _, row := range []struct {
		query string // supplied startup timeout option
		want  string // bounded timeout passed to lib/pq
	}{
		{"", "5"},
		{"&connect_timeout=0", "5"},
		{"&connect_timeout=-2", "5"},
		{"&connect_timeout=1", "1"},
		{"&connect_timeout=300", "5"},
	} {
		t.Run(row.query, func(t *testing.T) {
			u, err := nativeTestURL("postgresql://fixture@127.0.0.1:55432/identity_test?sslmode=disable&TimeZone=UTC" + row.query)
			require.NoError(t, err)
			require.Equal(t, "disable", u.Query().Get("sslmode"))
			require.Equal(t, "UTC", u.Query().Get("TimeZone"))
			require.Equal(t, row.want, u.Query().Get("connect_timeout"))
			for _, database := range []string{"identity_test", "gettok_verification_scratch"} {
				u.Path = "/" + database
				options, err := pq.ParseURL(u.String())
				require.NoError(t, err)
				require.Equal(t, 1, strings.Count(options, "dbname="))
				require.Contains(t, options, "dbname='"+database+"'")
				require.Contains(t, options, "host='127.0.0.1'")
				require.Contains(t, options, "port='55432'")
				require.Contains(t, options, "connect_timeout='"+row.want+"'")
			}
		})
	}
	for _, query := range []string{"connect_timeout=invalid", "connect_timeout=1&connect_timeout=2"} {
		_, err := nativeTestURL("postgres://127.0.0.1/identity_test?" + query)
		require.Error(t, err)
	}
}
