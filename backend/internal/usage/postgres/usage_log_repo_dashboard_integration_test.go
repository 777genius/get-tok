//go:build integration

package postgres

import (
	"time"

	"github.com/TokenFlux/TokenRouter/internal/apikey"
	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/pkg/timezone"
	"github.com/TokenFlux/TokenRouter/internal/provider"
	"github.com/TokenFlux/TokenRouter/internal/settings/preaggregation"
	"github.com/TokenFlux/TokenRouter/internal/usage"
)

// usage_log_repo_dashboard_integration_test.go verifies personal resource scope
// and Key dashboard totals with migrated PostgreSQL rows. Totals combine
// retained usage, local today, nonnull duration
// averages, and recent raw rates. A Kathmandu fixture compares raw and analytics
// results with future records, then deletes older rows to check that stale
// rollup history does not enlarge the retained total.

// TestAPIKeyDashboardAnalyticsParity records usage around Kathmandu dates with
// null timings, zero costs, and future instants. It compares complete
// raw/analytics dashboards, then checks parity after retained raw history
// shrinks.
func (s *UsageLogRepoSuite) TestAPIKeyDashboardAnalyticsParity() {
	user := mustCreateUser(s.T(), s.client, &identity.User{Email: "key-analytics@test.local"})
	key := mustCreateApiKey(s.T(), s.client, &apikey.APIKey{UserID: user.ID, Key: "key-analytics"})
	p := mustCreateProvider(s.T(), s.client, &provider.Record{Name: "key-analytics"})
	loc, err := time.LoadLocation("Asia/Kathmandu")
	s.Require().NoError(err)
	s.repo.calendar = timezone.NewCalendar(loc)
	now := time.Now().UTC().Truncate(time.Second)
	for i, at := range []time.Time{now.Add(-120 * time.Hour), now.Add(-53 * time.Hour), now.Add(-12 * time.Hour), now.Add(-2 * time.Hour), now.Add(48 * time.Hour)} {
		log := s.createUsageLog(user, key, p, 10+i, 5+i, float64(i), at)
		if i%2 == 0 {
			_, err = s.tx.ExecContext(s.ctx, "UPDATE usage_logs SET duration_ms=$1 WHERE id=$2", i*100, log.ID)
			s.Require().NoError(err)
		}
	}
	want, err := s.repo.GetAPIKeyDashboardStats(s.ctx, key.ID)
	s.Require().NoError(err)
	start := now.Add(-72 * time.Hour).Truncate(time.Hour)
	watermark := now.Add(-3 * time.Hour)
	aggregation := NewAggregationStoreWithSQL(s.tx, s.repo.calendar)
	s.Require().NoError(aggregation.AggregateUsageAnalyticsRange(s.ctx, start, watermark))
	s.Require().NoError(aggregation.SaveUsageAnalyticsAggregationState(s.ctx, &usage.UsageAnalyticsAggregationState{
		LiveWatermark: watermark, CoverageStart: &start, Phase: "idle",
	}))
	s.repo.preAggregation = preaggregation.NewPreAggregationSettingsService(nil, &preaggregation.Options{
		Usage: preaggregation.UsageOptions{Enabled: true, IntervalSeconds: 60},
	})
	_, ok, err := s.repo.getAPIKeyDashboardStatsFromAnalytics(s.ctx, key.ID)
	s.Require().NoError(err)
	s.Require().True(ok)
	got, err := s.repo.GetAPIKeyDashboardStats(s.ctx, key.ID)
	s.Require().NoError(err)
	s.Require().Equal(want, got)
	// Delete retained history without rebuilding old buckets, then compare readers;
	// the key's oldest remaining raw record must bound its retained analytics
	// total.
	_, err = s.tx.ExecContext(s.ctx, "DELETE FROM usage_logs WHERE api_key_id=$1 AND created_at<$2", key.ID, now.Add(-24*time.Hour))
	s.Require().NoError(err)
	got, err = s.repo.GetAPIKeyDashboardStats(s.ctx, key.ID)
	s.Require().NoError(err)
	s.repo.preAggregation = nil
	want, err = s.repo.GetAPIKeyDashboardStats(s.ctx, key.ID)
	s.Require().NoError(err)
	s.Require().Equal(want, got)
}

// TestPersonalDashboardExcludesTeamAttributionAfterMembershipChange records personal
// and team usage before the actor becomes team owner. Both reads must retain
// only persisted personal rows, including key counts and recent token rates.
func (s *UsageLogRepoSuite) TestPersonalDashboardExcludesTeamAttributionAfterMembershipChange() {
	owner := mustCreateUser(s.T(), s.client, &identity.User{Email: "personal-dashboard@test.local"})
	member := mustCreateUser(s.T(), s.client, &identity.User{Email: "personal-dashboard-member@test.local"})
	p := mustCreateProvider(s.T(), s.client, &provider.Record{Name: "personal-dashboard"})
	team, err := s.client.Team.Create().SetName("personal-dashboard-team").SetStatus("active").SetMemberLimit(10).Save(s.ctx)
	s.Require().NoError(err)
	personal := mustCreateApiKey(s.T(), s.client, &apikey.APIKey{UserID: owner.ID, Key: "personal-dashboard-personal"})
	ownerTeam := mustCreateApiKey(s.T(), s.client, &apikey.APIKey{UserID: owner.ID, TeamID: &team.ID, Key: "personal-dashboard-team"})
	memberTeam := mustCreateApiKey(s.T(), s.client, &apikey.APIKey{UserID: member.ID, TeamID: &team.ID, Key: "personal-dashboard-member"})
	at := time.Now().UTC()
	for i, key := range []*apikey.APIKey{personal, ownerTeam, memberTeam} {
		_, err = s.repo.Create(s.ctx, &usage.UsageLog{
			UserID: key.UserID, BillingUserID: owner.ID, TeamID: key.TeamID,
			APIKeyID: key.ID, ProviderID: p.ID, RequestID: key.Key,
			Model: "personal-dashboard", CreatedAt: at,
			InputTokens: 10 + i*100, OutputTokens: 20 + i*100,
			ActualCost: 0.1 + float64(i), TotalCost: 0.1 + float64(i),
		})
		s.Require().NoError(err)
	}
	want, err := s.repo.GetPersonalDashboardStats(s.ctx, owner.ID)
	s.Require().NoError(err)
	s.Require().Equal(int64(1), want.TotalAPIKeys)
	s.Require().Equal(int64(1), want.ActiveAPIKeys)
	s.Require().Equal(int64(1), want.TotalRequests)
	s.Require().Equal(int64(30), want.TotalTokens)
	s.Require().Equal(int64(6), want.Tpm)
	s.Require().InDelta(0.1, want.TotalActualCost, 0.000001)
	_, err = s.client.TeamMembership.Create().SetTeamID(team.ID).SetUserID(owner.ID).SetRole("owner").Save(s.ctx)
	s.Require().NoError(err)
	// Publishing ownership after the first read must not widen any component of
	// a personal dashboard; query scope remains tied to each row's stored attribution.
	got, err := s.repo.GetPersonalDashboardStats(s.ctx, owner.ID)
	s.Require().NoError(err)
	s.Require().Equal(want, got)
	broad, err := s.repo.GetUserDashboardStats(s.ctx, owner.ID)
	s.Require().NoError(err)
	s.Require().Equal(int64(3), broad.TotalRequests)
}
