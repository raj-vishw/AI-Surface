// Package analytics implements Phase 14's read-only aggregate queries
// over Phase 2-13's own tables — no new source-of-truth data is ever
// introduced here, only COUNT/GROUP BY/date_trunc aggregation over rows
// those phases already write (phase14.md's own "do not create duplicate
// versions of these systems"). Every query is scoped by target_id (this
// platform's authorization boundary — see internal/service/analytics's
// package doc comment for why) and, where meaningful, a [from, to) time
// window.
//
// This package is the one exception to the "engine has zero repository
// dependency" split every other phase's engine package follows
// (internal/correlation, internal/ruleengine, internal/ai): analytics is
// intrinsically a database-aggregation concern, so — like `pagination`
// defining `Page[T]` — the small, data-only result shapes below live
// here rather than forcing a parallel, DB-free copy of each one into
// internal/analytics. internal/analytics (the service-shaped layer) adds
// caching, time-range validation, and interval selection on top of this
// interface; it never talks to a database directly.
package analytics

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TimeRange is an explicit [Start, End) window — never an ambiguous
// "last N units" string once it reaches this layer (phase14.md §21: "use
// explicit start/end timestamps internally").
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Bucket is one time-series data point — a count of some event type
// falling within [BucketStart, next bucket).
type Bucket struct {
	BucketStart time.Time
	Count       int
}

// NamedCount is a generic (label, count) pair — used for every
// "breakdown by X" query (severity, status, category, rule, provider,
// model, tool, stage, indicator type, ...).
type NamedCount struct {
	Name  string
	Count int
}

// RiskBucket is one time-bucketed risk-trend data point (phase14.md §6).
type RiskBucket struct {
	BucketStart   time.Time
	AverageScore  float64
	MaxScore      int
	CriticalCount int
	HighCount     int
}

// Repository is every aggregate query Phase 14's analytics layer needs.
// Every method is read-only; none has any way to mutate a row.
type Repository interface {
	// --- overview / point-in-time counts ---
	CountAssets(ctx context.Context, targetID uuid.UUID) (total int, err error)
	CountAssetsByStatus(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error)
	CountOpenFindings(ctx context.Context, targetID uuid.UUID) (int, error)
	CountOpenAlerts(ctx context.Context, targetID uuid.UUID) (int, error)
	CountActiveInvestigations(ctx context.Context, targetID uuid.UUID) (int, error)
	CountCriticalHighRiskAssets(ctx context.Context, targetID uuid.UUID) (critical int, high int, err error)
	CountOpenCorrelations(ctx context.Context, targetID uuid.UUID) (int, error)
	CountIntelligenceRecords(ctx context.Context, targetID uuid.UUID) (int, error)

	// --- risk ---
	RiskTrend(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]RiskBucket, error)
	LatestRiskDistribution(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error) // by severity bucket
	// LatestRiskAverage averages the most recent score per (entity_type,
	// entity_id) — the input internal/analytics.SecurityPosture derives
	// its score from (phase14.md §5).
	LatestRiskAverage(ctx context.Context, targetID uuid.UUID) (average float64, scoredEntities int, err error)

	// --- alerts ---
	AlertsOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	AlertsBySeverity(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	AlertsByStatus(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	AlertsByRule(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)

	// --- detections ---
	DetectionMatchesOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	MatchesByRule(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	MatchesBySeverity(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	RuleStatusCounts(ctx context.Context, targetID uuid.UUID) (enabled int, disabled int, err error)
	// RuleAlertConversion returns, per rule, how many of its matches
	// produced an alert in r — the platform's own "match rate" data,
	// never labeled a false-positive rate (phase14.md §8).
	RuleAlertConversion(ctx context.Context, targetID uuid.UUID, r TimeRange) (map[string]RuleConversion, error)

	// --- findings ---
	FindingsBySeverity(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	FindingsByCategory(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	FindingsOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	FindingsOpenVsResolved(ctx context.Context, targetID uuid.UUID) (open int, resolved int, err error)
	TopAffectedAssets(ctx context.Context, targetID uuid.UUID, r TimeRange, limit int) ([]NamedCount, error)

	// --- assets / attack surface ---
	AssetsByType(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error)
	NewAssetsOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	RemovedAssetsCount(ctx context.Context, targetID uuid.UUID, r TimeRange) (int, error)

	// --- correlations / attack chains ---
	CorrelationsOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	CorrelationsBySeverity(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	CorrelationsByConfidence(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	CorrelationsByStatus(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	CorrelationsByStrategy(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	AttackChainsOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	AttackChainsBySeverity(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	AttackChainsByConfidence(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	CommonAttackStages(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)

	// --- investigations (also serves "incidents" — see package doc
	// comment on the Phase 9 consolidation this mirrors) ---
	InvestigationsOpenedOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	InvestigationsClosedOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	InvestigationsBySeverity(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	InvestigationsByStatus(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	MeanInvestigationDurationSeconds(ctx context.Context, targetID uuid.UUID, r TimeRange) (float64, int, error)

	// --- intelligence ---
	IntelligenceByIndicatorType(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error)
	IntelligenceByProvider(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error)
	IntelligenceByConfidence(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error)
	ExpiredIntelligenceCount(ctx context.Context, targetID uuid.UUID) (int, error)

	// --- AI usage (Phase 13) ---
	AIRequestsOverTime(ctx context.Context, targetID uuid.UUID, r TimeRange, interval string) ([]Bucket, error)
	AIRequestsByTaskType(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	AIRequestsByProvider(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
	AIAverageLatencyMS(ctx context.Context, targetID uuid.UUID, r TimeRange) (float64, error)
	AITokenTotals(ctx context.Context, targetID uuid.UUID, r TimeRange) (input int64, output int64, err error)
	AIFailureCount(ctx context.Context, targetID uuid.UUID, r TimeRange) (int, error)
	AIToolCallsByTool(ctx context.Context, targetID uuid.UUID, r TimeRange) ([]NamedCount, error)
}

// RuleConversion is one rule's own match/alert/dismissal counters
// (phase14.md §8) — deliberately never labeled a "false-positive rate":
// this platform has no ground-truth confirmation of which matches were
// genuinely benign, only how many were dismissed by an analyst.
type RuleConversion struct {
	Matches   int
	Alerts    int
	Dismissed int
}
