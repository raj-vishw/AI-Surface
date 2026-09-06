package analytics

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// fakeRepository implements analyticsrepo.Repository with per-target
// call counting — used to verify caching and cache-isolation behavior
// without a database.
type fakeRepository struct {
	calls map[uuid.UUID]int
}

func newFakeRepository() *fakeRepository { return &fakeRepository{calls: map[uuid.UUID]int{}} }

func (f *fakeRepository) CountAssets(_ context.Context, targetID uuid.UUID) (int, error) {
	f.calls[targetID]++
	return 1, nil
}
func (f *fakeRepository) CountAssetsByStatus(context.Context, uuid.UUID) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) CountOpenFindings(context.Context, uuid.UUID) (int, error) { return 0, nil }
func (f *fakeRepository) CountOpenAlerts(context.Context, uuid.UUID) (int, error)   { return 0, nil }
func (f *fakeRepository) CountActiveInvestigations(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (f *fakeRepository) CountCriticalHighRiskAssets(context.Context, uuid.UUID) (int, int, error) {
	return 0, 0, nil
}
func (f *fakeRepository) CountOpenCorrelations(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (f *fakeRepository) CountIntelligenceRecords(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (f *fakeRepository) RiskTrend(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.RiskBucket, error) {
	return nil, nil
}
func (f *fakeRepository) LatestRiskDistribution(context.Context, uuid.UUID) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) LatestRiskAverage(context.Context, uuid.UUID) (float64, int, error) {
	return 0, 0, nil
}
func (f *fakeRepository) AlertsOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) AlertsBySeverity(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) AlertsByStatus(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) AlertsByRule(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) DetectionMatchesOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) MatchesByRule(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) MatchesBySeverity(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) RuleStatusCounts(context.Context, uuid.UUID) (int, int, error) {
	return 0, 0, nil
}
func (f *fakeRepository) RuleAlertConversion(context.Context, uuid.UUID, analyticsrepo.TimeRange) (map[string]analyticsrepo.RuleConversion, error) {
	return nil, nil
}
func (f *fakeRepository) FindingsBySeverity(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) FindingsByCategory(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) FindingsOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) FindingsOpenVsResolved(context.Context, uuid.UUID) (int, int, error) {
	return 0, 0, nil
}
func (f *fakeRepository) TopAffectedAssets(context.Context, uuid.UUID, analyticsrepo.TimeRange, int) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) AssetsByType(context.Context, uuid.UUID) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) NewAssetsOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) RemovedAssetsCount(context.Context, uuid.UUID, analyticsrepo.TimeRange) (int, error) {
	return 0, nil
}
func (f *fakeRepository) CorrelationsOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) CorrelationsBySeverity(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) CorrelationsByConfidence(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) CorrelationsByStatus(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) CorrelationsByStrategy(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) AttackChainsOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) AttackChainsBySeverity(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) AttackChainsByConfidence(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) CommonAttackStages(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) InvestigationsOpenedOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) InvestigationsClosedOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) InvestigationsBySeverity(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) InvestigationsByStatus(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) MeanInvestigationDurationSeconds(context.Context, uuid.UUID, analyticsrepo.TimeRange) (float64, int, error) {
	return 0, 0, nil
}
func (f *fakeRepository) IntelligenceByIndicatorType(context.Context, uuid.UUID) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) IntelligenceByProvider(context.Context, uuid.UUID) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) IntelligenceByConfidence(context.Context, uuid.UUID) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) ExpiredIntelligenceCount(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (f *fakeRepository) AIRequestsOverTime(context.Context, uuid.UUID, analyticsrepo.TimeRange, string) ([]analyticsrepo.Bucket, error) {
	return nil, nil
}
func (f *fakeRepository) AIRequestsByTaskType(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) AIRequestsByProvider(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}
func (f *fakeRepository) AIAverageLatencyMS(context.Context, uuid.UUID, analyticsrepo.TimeRange) (float64, error) {
	return 0, nil
}
func (f *fakeRepository) AITokenTotals(context.Context, uuid.UUID, analyticsrepo.TimeRange) (int64, int64, error) {
	return 0, 0, nil
}
func (f *fakeRepository) AIFailureCount(context.Context, uuid.UUID, analyticsrepo.TimeRange) (int, error) {
	return 0, nil
}
func (f *fakeRepository) AIToolCallsByTool(context.Context, uuid.UUID, analyticsrepo.TimeRange) ([]analyticsrepo.NamedCount, error) {
	return nil, nil
}

var _ analyticsrepo.Repository = (*fakeRepository)(nil)

func TestService_Overview_CachesPerTarget(t *testing.T) {
	repo := newFakeRepository()
	svc := NewService(repo, NewCache(time.Minute))

	targetA := uuid.New()
	targetB := uuid.New()

	if _, err := svc.Overview(context.Background(), targetA); err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if _, err := svc.Overview(context.Background(), targetA); err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if repo.calls[targetA] != 1 {
		t.Errorf("repo.calls[targetA] = %d, want 1 (second call should hit cache)", repo.calls[targetA])
	}

	if _, err := svc.Overview(context.Background(), targetB); err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if repo.calls[targetB] != 1 {
		t.Errorf("repo.calls[targetB] = %d, want 1", repo.calls[targetB])
	}
	if repo.calls[targetA] != 1 {
		t.Error("calling Overview for targetB incorrectly triggered a fresh query for targetA — cache isolation broken")
	}
}

func TestService_TimeSeries_RejectsUnknownMetric(t *testing.T) {
	svc := NewService(newFakeRepository(), nil)
	r, err := ResolveRange(Range7d, time.Time{}, time.Time{}, "")
	if err != nil {
		t.Fatalf("ResolveRange: %v", err)
	}
	if _, err := svc.TimeSeries(context.Background(), uuid.New(), "not_a_real_metric", r); err == nil {
		t.Fatal("expected an error for an unrecognized metric")
	}
}

func TestService_TimeSeries_AcceptsEveryValidMetric(t *testing.T) {
	svc := NewService(newFakeRepository(), nil)
	r, err := ResolveRange(Range7d, time.Time{}, time.Time{}, "")
	if err != nil {
		t.Fatalf("ResolveRange: %v", err)
	}
	for _, m := range ValidMetrics() {
		if _, err := svc.TimeSeries(context.Background(), uuid.New(), Metric(m), r); err != nil {
			t.Errorf("TimeSeries(%q): %v", m, err)
		}
	}
}

func TestSecurityPosture_NoScoredEntitiesIsHonestZero(t *testing.T) {
	svc := NewService(newFakeRepository(), nil)
	p, err := svc.Posture(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("Posture: %v", err)
	}
	if p.ScoredEntities != 0 || p.Score != 0 {
		t.Errorf("Posture with no data = %+v, want a zero score, not a fabricated 100", p)
	}
}
