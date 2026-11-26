package usage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// service_test.go verifies that personal resource restrictions survive missing
// optional repository capabilities. The service receives no usable broader
// repository, so a fallback that discards the restriction cannot hide behind
// plausible fixture data or an unchanged HTTP response shape.

// TestPersonalQueriesRejectMissingScopeCapabilities exercises each reduced-reader
// fallback with personal-only scope. Every call must return the scope error
// before attempting a legacy query that cannot represent persisted team exclusion.
func TestPersonalQueriesRejectMissingScopeCapabilities(t *testing.T) {
	service := NewUsageService(nil, QueryReaders{})
	filters := UsageLogFilters{UserID: 42, PersonalOnly: true}
	start := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	_, err := service.GetPersonalDashboardStats(context.Background(), 42)
	require.ErrorIs(t, err, ErrUsageScopeUnsupported)
	_, err = service.GetUsageTrendWithFilters(context.Background(), start, end, "hour", filters)
	require.ErrorIs(t, err, ErrUsageScopeUnsupported)
	_, err = service.GetModelStatsWithFiltersBySource(context.Background(), start, end, filters, ModelSourceRequested)
	require.ErrorIs(t, err, ErrUsageScopeUnsupported)
	_, err = service.GetGroupStatsWithFilters(context.Background(), start, end, filters)
	require.ErrorIs(t, err, ErrUsageScopeUnsupported)
}
