package analytics

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"

	analyticsrepo "ai-surface-platform/internal/repository/analytics"
)

// Metric names one time-series this package can produce (phase14.md
// §54's `GET /analytics/timeseries?metric=...`, adapted to CLI — see
// cmd/cli/commands/analytics.go). A closed, validated set — never an
// arbitrary caller-supplied SQL fragment.
type Metric string

// Recognized time-series metrics.
const (
	MetricAlerts               Metric = "alerts"
	MetricDetections           Metric = "detections"
	MetricFindings             Metric = "findings"
	MetricNewAssets            Metric = "new_assets"
	MetricCorrelations         Metric = "correlations"
	MetricAttackChains         Metric = "attack_chains"
	MetricAIRequests           Metric = "ai_requests"
	MetricInvestigationsOpened Metric = "investigations_opened"
	MetricInvestigationsClosed Metric = "investigations_closed"
)

var validMetrics = map[Metric]func(*Service, context.Context, uuid.UUID, TimeRange) ([]analyticsrepo.Bucket, error){
	MetricAlerts:               (*Service).timeSeriesAlerts,
	MetricDetections:           (*Service).timeSeriesDetections,
	MetricFindings:             (*Service).timeSeriesFindings,
	MetricNewAssets:            (*Service).timeSeriesNewAssets,
	MetricCorrelations:         (*Service).timeSeriesCorrelations,
	MetricAttackChains:         (*Service).timeSeriesAttackChains,
	MetricAIRequests:           (*Service).timeSeriesAIRequests,
	MetricInvestigationsOpened: (*Service).timeSeriesInvestigationsOpened,
	MetricInvestigationsClosed: (*Service).timeSeriesInvestigationsClosed,
}

// ValidMetrics returns every recognized metric name, sorted — used for
// CLI help text and validation error messages.
func ValidMetrics() []string {
	names := make([]string, 0, len(validMetrics))
	for m := range validMetrics {
		names = append(names, string(m))
	}
	sort.Strings(names)
	return names
}

// TimeSeries implements phase14.md §54: a single, validated,
// allowlisted dispatch point for every time-series metric this package
// supports (phase14.md §54: "validate all parameters").
func (s *Service) TimeSeries(ctx context.Context, targetID uuid.UUID, metric Metric, r TimeRange) ([]analyticsrepo.Bucket, error) {
	fn, ok := validMetrics[metric]
	if !ok {
		return nil, fmt.Errorf("unrecognized metric %q — must be one of %v", metric, ValidMetrics())
	}
	return cached(s, targetID, "timeseries:"+string(metric), r, Filters{}, func() ([]analyticsrepo.Bucket, error) {
		return fn(s, ctx, targetID, r)
	})
}

func (s *Service) timeSeriesAlerts(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.AlertsOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
func (s *Service) timeSeriesDetections(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.DetectionMatchesOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
func (s *Service) timeSeriesFindings(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.FindingsOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
func (s *Service) timeSeriesNewAssets(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.NewAssetsOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
func (s *Service) timeSeriesCorrelations(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.CorrelationsOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
func (s *Service) timeSeriesAttackChains(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.AttackChainsOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
func (s *Service) timeSeriesAIRequests(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.AIRequestsOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
func (s *Service) timeSeriesInvestigationsOpened(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.InvestigationsOpenedOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
func (s *Service) timeSeriesInvestigationsClosed(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]analyticsrepo.Bucket, error) {
	return s.repo.InvestigationsClosedOverTime(ctx, targetID, r.toRepo(), r.Interval)
}
