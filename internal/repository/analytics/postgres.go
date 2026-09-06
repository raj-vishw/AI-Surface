package analytics

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"ai-recon-platform/internal/database"
	apperrors "ai-recon-platform/internal/errors"
)

// PostgresRepository implements Repository — every method is a read-only
// COUNT/GROUP BY/date_trunc aggregate query, never a write.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var _ Repository = (*PostgresRepository)(nil)

// dateTrunc maps this package's own "hour"/"day"/"week" interval
// vocabulary directly onto Postgres's date_trunc field names — kept as
// an explicit allowlist (never string-interpolated from unchecked input)
// so a query can never be built with an unexpected trunc field.
func dateTrunc(interval string) (string, error) {
	switch interval {
	case "hour", "day", "week":
		return interval, nil
	default:
		return "", apperrors.NewValidation(fmt.Sprintf("unsupported interval %q", interval), nil)
	}
}

func (r *PostgresRepository) queryBuckets(ctx context.Context, sql string, args ...any) ([]Bucket, error) {
	rows, err := r.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, apperrors.NewDatabase("querying analytics time series", err)
	}
	defer rows.Close()
	var out []Bucket
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.BucketStart, &b.Count); err != nil {
			return nil, apperrors.NewDatabase("scanning analytics bucket", err)
		}
		out = append(out, b)
	}
	return out, apperrors.NewDatabase("iterating analytics buckets", rows.Err())
}

func (r *PostgresRepository) queryNamedCounts(ctx context.Context, sql string, args ...any) ([]NamedCount, error) {
	rows, err := r.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, apperrors.NewDatabase("querying analytics breakdown", err)
	}
	defer rows.Close()
	var out []NamedCount
	for rows.Next() {
		var n NamedCount
		if err := rows.Scan(&n.Name, &n.Count); err != nil {
			return nil, apperrors.NewDatabase("scanning analytics breakdown row", err)
		}
		out = append(out, n)
	}
	return out, apperrors.NewDatabase("iterating analytics breakdown", rows.Err())
}

func (r *PostgresRepository) queryCount(ctx context.Context, sql string, args ...any) (int, error) {
	var n int
	err := r.db.QueryRow(ctx, sql, args...).Scan(&n)
	if err != nil {
		return 0, apperrors.NewDatabase("querying analytics count", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------
// overview / point-in-time counts
// ---------------------------------------------------------------------

// CountAssets implements Repository.
func (r *PostgresRepository) CountAssets(ctx context.Context, targetID uuid.UUID) (int, error) {
	return r.queryCount(ctx, `SELECT count(*) FROM assets WHERE target_id = $1`, targetID)
}

// CountAssetsByStatus implements Repository.
func (r *PostgresRepository) CountAssetsByStatus(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `SELECT status, count(*) FROM assets WHERE target_id = $1 GROUP BY status ORDER BY status`, targetID)
}

// CountOpenFindings implements Repository.
func (r *PostgresRepository) CountOpenFindings(ctx context.Context, targetID uuid.UUID) (int, error) {
	return r.queryCount(ctx, `SELECT count(*) FROM findings WHERE target_id = $1 AND status = 'open'`, targetID)
}

// CountOpenAlerts implements Repository.
func (r *PostgresRepository) CountOpenAlerts(ctx context.Context, targetID uuid.UUID) (int, error) {
	return r.queryCount(ctx, `SELECT count(*) FROM alerts WHERE target_id = $1 AND status IN ('open','acknowledged','investigating')`, targetID)
}

// CountActiveInvestigations implements Repository.
func (r *PostgresRepository) CountActiveInvestigations(ctx context.Context, targetID uuid.UUID) (int, error) {
	return r.queryCount(ctx, `SELECT count(*) FROM investigations WHERE target_id = $1 AND status <> 'closed'`, targetID)
}

// CountCriticalHighRiskAssets counts assets whose most recent risk score
// (per asset — a DISTINCT ON on calculated_at DESC, mirroring
// RiskRepository.GetLatestRiskScore's own "most recent wins" semantics)
// is critical/high severity.
func (r *PostgresRepository) CountCriticalHighRiskAssets(ctx context.Context, targetID uuid.UUID) (int, int, error) {
	rows, err := r.db.Query(ctx, `
		SELECT severity, count(*) FROM (
			SELECT DISTINCT ON (entity_id) entity_id, severity
			FROM risk_scores
			WHERE target_id = $1 AND entity_type = 'asset'
			ORDER BY entity_id, calculated_at DESC
		) latest
		WHERE severity IN ('critical','high')
		GROUP BY severity`, targetID)
	if err != nil {
		return 0, 0, apperrors.NewDatabase("counting critical/high risk assets", err)
	}
	defer rows.Close()
	var critical, high int
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return 0, 0, apperrors.NewDatabase("scanning risk severity row", err)
		}
		switch severity {
		case "critical":
			critical = count
		case "high":
			high = count
		}
	}
	return critical, high, apperrors.NewDatabase("iterating risk severities", rows.Err())
}

// CountOpenCorrelations implements Repository.
func (r *PostgresRepository) CountOpenCorrelations(ctx context.Context, targetID uuid.UUID) (int, error) {
	return r.queryCount(ctx, `SELECT count(*) FROM correlations WHERE target_id = $1 AND status IN ('open','investigating')`, targetID)
}

// CountIntelligenceRecords implements Repository.
func (r *PostgresRepository) CountIntelligenceRecords(ctx context.Context, targetID uuid.UUID) (int, error) {
	return r.queryCount(ctx, `SELECT count(*) FROM intelligence_records WHERE target_id = $1`, targetID)
}

// ---------------------------------------------------------------------
// risk
// ---------------------------------------------------------------------

// RiskTrend implements Repository.
func (r *PostgresRepository) RiskTrend(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]RiskBucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', calculated_at) AS bucket,
			avg(score), max(score),
			count(*) FILTER (WHERE severity = 'critical'),
			count(*) FILTER (WHERE severity = 'high')
		FROM risk_scores
		WHERE target_id = $1 AND calculated_at >= $2 AND calculated_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
	if err != nil {
		return nil, apperrors.NewDatabase("querying risk trend", err)
	}
	defer rows.Close()
	var out []RiskBucket
	for rows.Next() {
		var b RiskBucket
		if err := rows.Scan(&b.BucketStart, &b.AverageScore, &b.MaxScore, &b.CriticalCount, &b.HighCount); err != nil {
			return nil, apperrors.NewDatabase("scanning risk trend row", err)
		}
		out = append(out, b)
	}
	return out, apperrors.NewDatabase("iterating risk trend", rows.Err())
}

// LatestRiskAverage implements Repository.
func (r *PostgresRepository) LatestRiskAverage(ctx context.Context, targetID uuid.UUID) (float64, int, error) {
	var avg *float64
	var n int
	err := r.db.QueryRow(ctx, `
		SELECT avg(score), count(*) FROM (
			SELECT DISTINCT ON (entity_type, entity_id) entity_type, entity_id, score
			FROM risk_scores WHERE target_id = $1
			ORDER BY entity_type, entity_id, calculated_at DESC
		) latest`, targetID).Scan(&avg, &n)
	if err != nil {
		return 0, 0, apperrors.NewDatabase("averaging latest risk scores", err)
	}
	if avg == nil {
		return 0, 0, nil
	}
	return *avg, n, nil
}

// LatestRiskDistribution implements Repository.
func (r *PostgresRepository) LatestRiskDistribution(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT severity, count(*) FROM (
			SELECT DISTINCT ON (entity_type, entity_id) entity_type, entity_id, severity
			FROM risk_scores WHERE target_id = $1
			ORDER BY entity_type, entity_id, calculated_at DESC
		) latest GROUP BY severity ORDER BY severity`, targetID)
}

// ---------------------------------------------------------------------
// alerts
// ---------------------------------------------------------------------

// AlertsOverTime implements Repository.
func (r *PostgresRepository) AlertsOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', created_at) AS bucket, count(*)
		FROM alerts WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// AlertsBySeverity implements Repository.
func (r *PostgresRepository) AlertsBySeverity(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT severity, count(*) FROM alerts
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY severity ORDER BY severity`, targetID, tr.Start, tr.End)
}

// AlertsByStatus implements Repository.
func (r *PostgresRepository) AlertsByStatus(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT status, count(*) FROM alerts
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY status ORDER BY status`, targetID, tr.Start, tr.End)
}

// AlertsByRule implements Repository.
func (r *PostgresRepository) AlertsByRule(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT ru.name, count(*) FROM alerts a
		JOIN detection_matches dm ON dm.id = a.detection_match_id
		JOIN rules ru ON ru.id = dm.rule_id
		WHERE a.target_id = $1 AND a.created_at >= $2 AND a.created_at < $3
		GROUP BY ru.name ORDER BY count(*) DESC`, targetID, tr.Start, tr.End)
}

// ---------------------------------------------------------------------
// detections
// ---------------------------------------------------------------------

// DetectionMatchesOverTime implements Repository.
func (r *PostgresRepository) DetectionMatchesOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', created_at) AS bucket, count(*)
		FROM detection_matches WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// MatchesByRule implements Repository.
func (r *PostgresRepository) MatchesByRule(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT ru.name, count(*) FROM detection_matches dm
		JOIN rules ru ON ru.id = dm.rule_id
		WHERE dm.target_id = $1 AND dm.created_at >= $2 AND dm.created_at < $3
		GROUP BY ru.name ORDER BY count(*) DESC`, targetID, tr.Start, tr.End)
}

// MatchesBySeverity implements Repository.
func (r *PostgresRepository) MatchesBySeverity(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT severity, count(*) FROM detection_matches
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY severity ORDER BY severity`, targetID, tr.Start, tr.End)
}

// RuleStatusCounts implements Repository.
func (r *PostgresRepository) RuleStatusCounts(ctx context.Context, targetID uuid.UUID) (int, int, error) {
	rows, err := r.db.Query(ctx, `SELECT status, count(*) FROM rules WHERE target_id = $1 GROUP BY status`, targetID)
	if err != nil {
		return 0, 0, apperrors.NewDatabase("counting rule statuses", err)
	}
	defer rows.Close()
	var enabled, disabled int
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return 0, 0, apperrors.NewDatabase("scanning rule status row", err)
		}
		if status == "enabled" {
			enabled = count
		} else {
			disabled += count
		}
	}
	return enabled, disabled, apperrors.NewDatabase("iterating rule statuses", rows.Err())
}

// RuleAlertConversion implements Repository. "Dismissed" counts alerts
// with status 'suppressed' — the closest analyst-dismissal-equivalent
// status this platform's Alert model has (see rule.AlertStatus); never
// labeled a false-positive rate (phase14.md §8).
func (r *PostgresRepository) RuleAlertConversion(ctx context.Context, targetID uuid.UUID, tr TimeRange) (map[string]RuleConversion, error) {
	rows, err := r.db.Query(ctx, `
		SELECT ru.name,
			count(DISTINCT dm.id) AS matches,
			count(DISTINCT a.id) AS alerts,
			count(DISTINCT a.id) FILTER (WHERE a.status = 'suppressed') AS dismissed
		FROM detection_matches dm
		JOIN rules ru ON ru.id = dm.rule_id
		LEFT JOIN alerts a ON a.detection_match_id = dm.id
		WHERE dm.target_id = $1 AND dm.created_at >= $2 AND dm.created_at < $3
		GROUP BY ru.name`, targetID, tr.Start, tr.End)
	if err != nil {
		return nil, apperrors.NewDatabase("querying rule alert conversion", err)
	}
	defer rows.Close()
	out := make(map[string]RuleConversion)
	for rows.Next() {
		var name string
		var c RuleConversion
		if err := rows.Scan(&name, &c.Matches, &c.Alerts, &c.Dismissed); err != nil {
			return nil, apperrors.NewDatabase("scanning rule alert conversion row", err)
		}
		out[name] = c
	}
	return out, apperrors.NewDatabase("iterating rule alert conversion", rows.Err())
}

// ---------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------

// FindingsBySeverity implements Repository.
func (r *PostgresRepository) FindingsBySeverity(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT severity, count(*) FROM findings
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY severity ORDER BY severity`, targetID, tr.Start, tr.End)
}

// FindingsByCategory implements Repository.
func (r *PostgresRepository) FindingsByCategory(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT category, count(*) FROM findings
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY category ORDER BY count(*) DESC`, targetID, tr.Start, tr.End)
}

// FindingsOverTime implements Repository.
func (r *PostgresRepository) FindingsOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', created_at) AS bucket, count(*)
		FROM findings WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// FindingsOpenVsResolved implements Repository.
func (r *PostgresRepository) FindingsOpenVsResolved(ctx context.Context, targetID uuid.UUID) (int, int, error) {
	var open, resolved int
	err := r.db.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'open'), count(*) FILTER (WHERE status = 'resolved')
		FROM findings WHERE target_id = $1`, targetID).Scan(&open, &resolved)
	if err != nil {
		return 0, 0, apperrors.NewDatabase("counting open vs resolved findings", err)
	}
	return open, resolved, nil
}

// TopAffectedAssets implements Repository.
func (r *PostgresRepository) TopAffectedAssets(ctx context.Context, targetID uuid.UUID, tr TimeRange, limit int) ([]NamedCount, error) {
	if limit <= 0 {
		limit = 10
	}
	return r.queryNamedCounts(ctx, `
		SELECT a.identity_key, count(*) FROM findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE f.target_id = $1 AND f.created_at >= $2 AND f.created_at < $3
		GROUP BY a.identity_key ORDER BY count(*) DESC LIMIT $4`, targetID, tr.Start, tr.End, limit)
}

// ---------------------------------------------------------------------
// assets / attack surface
// ---------------------------------------------------------------------

// AssetsByType implements Repository.
func (r *PostgresRepository) AssetsByType(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `SELECT type, count(*) FROM assets WHERE target_id = $1 GROUP BY type ORDER BY count(*) DESC`, targetID)
}

// NewAssetsOverTime implements Repository.
func (r *PostgresRepository) NewAssetsOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', first_seen) AS bucket, count(*)
		FROM assets WHERE target_id = $1 AND first_seen >= $2 AND first_seen < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// RemovedAssetsCount implements Repository.
func (r *PostgresRepository) RemovedAssetsCount(ctx context.Context, targetID uuid.UUID, tr TimeRange) (int, error) {
	return r.queryCount(ctx, `
		SELECT count(*) FROM assets
		WHERE target_id = $1 AND status IN ('inactive','retired') AND updated_at >= $2 AND updated_at < $3`,
		targetID, tr.Start, tr.End)
}

// ---------------------------------------------------------------------
// correlations / attack chains
// ---------------------------------------------------------------------

// CorrelationsOverTime implements Repository.
func (r *PostgresRepository) CorrelationsOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', created_at) AS bucket, count(*)
		FROM correlations WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// CorrelationsBySeverity implements Repository.
func (r *PostgresRepository) CorrelationsBySeverity(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT severity, count(*) FROM correlations
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3 GROUP BY severity ORDER BY severity`,
		targetID, tr.Start, tr.End)
}

// CorrelationsByConfidence implements Repository.
func (r *PostgresRepository) CorrelationsByConfidence(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT confidence, count(*) FROM correlations
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3 GROUP BY confidence ORDER BY confidence`,
		targetID, tr.Start, tr.End)
}

// CorrelationsByStatus implements Repository.
func (r *PostgresRepository) CorrelationsByStatus(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT status, count(*) FROM correlations
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3 GROUP BY status ORDER BY status`,
		targetID, tr.Start, tr.End)
}

// CorrelationsByStrategy implements Repository.
func (r *PostgresRepository) CorrelationsByStrategy(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT DISTINCT ce.strategy_id, count(DISTINCT ce.correlation_id) FROM correlation_edges ce
		JOIN correlations c ON c.id = ce.correlation_id
		WHERE c.target_id = $1 AND c.created_at >= $2 AND c.created_at < $3
		GROUP BY ce.strategy_id ORDER BY count(DISTINCT ce.correlation_id) DESC`, targetID, tr.Start, tr.End)
}

// AttackChainsOverTime implements Repository.
func (r *PostgresRepository) AttackChainsOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', ac.created_at) AS bucket, count(*)
		FROM attack_chains ac JOIN correlations c ON c.id = ac.correlation_id
		WHERE c.target_id = $1 AND ac.created_at >= $2 AND ac.created_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// AttackChainsBySeverity implements Repository.
func (r *PostgresRepository) AttackChainsBySeverity(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT ac.severity, count(*) FROM attack_chains ac JOIN correlations c ON c.id = ac.correlation_id
		WHERE c.target_id = $1 AND ac.created_at >= $2 AND ac.created_at < $3
		GROUP BY ac.severity ORDER BY ac.severity`, targetID, tr.Start, tr.End)
}

// AttackChainsByConfidence implements Repository.
func (r *PostgresRepository) AttackChainsByConfidence(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT ac.confidence, count(*) FROM attack_chains ac JOIN correlations c ON c.id = ac.correlation_id
		WHERE c.target_id = $1 AND ac.created_at >= $2 AND ac.created_at < $3
		GROUP BY ac.confidence ORDER BY ac.confidence`, targetID, tr.Start, tr.End)
}

// CommonAttackStages implements Repository.
func (r *PostgresRepository) CommonAttackStages(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT s.stage, count(*) FROM attack_chain_stages s
		JOIN attack_chains ac ON ac.id = s.attack_chain_id
		JOIN correlations c ON c.id = ac.correlation_id
		WHERE c.target_id = $1 AND ac.created_at >= $2 AND ac.created_at < $3
		GROUP BY s.stage ORDER BY count(*) DESC`, targetID, tr.Start, tr.End)
}

// ---------------------------------------------------------------------
// investigations (also serves "incidents" — see repository.go doc comment)
// ---------------------------------------------------------------------

// InvestigationsOpenedOverTime implements Repository.
func (r *PostgresRepository) InvestigationsOpenedOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', created_at) AS bucket, count(*)
		FROM investigations WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// InvestigationsClosedOverTime implements Repository.
func (r *PostgresRepository) InvestigationsClosedOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', closed_at) AS bucket, count(*)
		FROM investigations WHERE target_id = $1 AND closed_at >= $2 AND closed_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// InvestigationsBySeverity implements Repository.
func (r *PostgresRepository) InvestigationsBySeverity(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT severity, count(*) FROM investigations
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3 AND severity <> ''
		GROUP BY severity ORDER BY severity`, targetID, tr.Start, tr.End)
}

// InvestigationsByStatus implements Repository.
func (r *PostgresRepository) InvestigationsByStatus(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT status, count(*) FROM investigations
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY status ORDER BY status`, targetID, tr.Start, tr.End)
}

// MeanInvestigationDurationSeconds averages closed_at - created_at over
// every investigation closed within tr (phase14.md §14: "document how it
// is calculated" — see docs/analytics/metrics.md).
func (r *PostgresRepository) MeanInvestigationDurationSeconds(ctx context.Context, targetID uuid.UUID, tr TimeRange) (float64, int, error) {
	var mean *float64
	var n int
	err := r.db.QueryRow(ctx, `
		SELECT avg(extract(epoch FROM (closed_at - created_at))), count(*)
		FROM investigations
		WHERE target_id = $1 AND closed_at IS NOT NULL AND closed_at >= $2 AND closed_at < $3`,
		targetID, tr.Start, tr.End).Scan(&mean, &n)
	if err != nil {
		return 0, 0, apperrors.NewDatabase("calculating mean investigation duration", err)
	}
	if mean == nil {
		return 0, 0, nil
	}
	return *mean, n, nil
}

// ---------------------------------------------------------------------
// intelligence
// ---------------------------------------------------------------------

// IntelligenceByIndicatorType implements Repository.
func (r *PostgresRepository) IntelligenceByIndicatorType(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `SELECT indicator_type, count(*) FROM intelligence_records WHERE target_id = $1 GROUP BY indicator_type ORDER BY count(*) DESC`, targetID)
}

// IntelligenceByProvider implements Repository.
func (r *PostgresRepository) IntelligenceByProvider(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `SELECT provider_id, count(*) FROM intelligence_records WHERE target_id = $1 GROUP BY provider_id ORDER BY count(*) DESC`, targetID)
}

// IntelligenceByConfidence implements Repository.
func (r *PostgresRepository) IntelligenceByConfidence(ctx context.Context, targetID uuid.UUID) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `SELECT confidence, count(*) FROM intelligence_records WHERE target_id = $1 GROUP BY confidence ORDER BY confidence`, targetID)
}

// ExpiredIntelligenceCount implements Repository.
func (r *PostgresRepository) ExpiredIntelligenceCount(ctx context.Context, targetID uuid.UUID) (int, error) {
	return r.queryCount(ctx, `SELECT count(*) FROM intelligence_records WHERE target_id = $1 AND expiration IS NOT NULL AND expiration < now()`, targetID)
}

// ---------------------------------------------------------------------
// AI usage (Phase 13)
// ---------------------------------------------------------------------

// AIRequestsOverTime implements Repository.
func (r *PostgresRepository) AIRequestsOverTime(ctx context.Context, targetID uuid.UUID, tr TimeRange, interval string) ([]Bucket, error) {
	trunc, err := dateTrunc(interval)
	if err != nil {
		return nil, err
	}
	return r.queryBuckets(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', created_at) AS bucket, count(*)
		FROM ai_requests WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY bucket ORDER BY bucket`, trunc), targetID, tr.Start, tr.End)
}

// AIRequestsByTaskType implements Repository.
func (r *PostgresRepository) AIRequestsByTaskType(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT task_type, count(*) FROM ai_requests
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY task_type ORDER BY count(*) DESC`, targetID, tr.Start, tr.End)
}

// AIRequestsByProvider implements Repository.
func (r *PostgresRepository) AIRequestsByProvider(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT resp.provider, count(*) FROM ai_responses resp
		JOIN ai_requests req ON req.id = resp.request_id
		WHERE req.target_id = $1 AND req.created_at >= $2 AND req.created_at < $3
		GROUP BY resp.provider ORDER BY count(*) DESC`, targetID, tr.Start, tr.End)
}

// AIAverageLatencyMS implements Repository.
func (r *PostgresRepository) AIAverageLatencyMS(ctx context.Context, targetID uuid.UUID, tr TimeRange) (float64, error) {
	var avg *float64
	err := r.db.QueryRow(ctx, `
		SELECT avg(resp.latency_ms) FROM ai_responses resp
		JOIN ai_requests req ON req.id = resp.request_id
		WHERE req.target_id = $1 AND req.created_at >= $2 AND req.created_at < $3`,
		targetID, tr.Start, tr.End).Scan(&avg)
	if err != nil {
		return 0, apperrors.NewDatabase("calculating average AI latency", err)
	}
	if avg == nil {
		return 0, nil
	}
	return *avg, nil
}

// AITokenTotals implements Repository.
func (r *PostgresRepository) AITokenTotals(ctx context.Context, targetID uuid.UUID, tr TimeRange) (int64, int64, error) {
	var input, output *int64
	err := r.db.QueryRow(ctx, `
		SELECT sum(resp.input_tokens), sum(resp.output_tokens) FROM ai_responses resp
		JOIN ai_requests req ON req.id = resp.request_id
		WHERE req.target_id = $1 AND req.created_at >= $2 AND req.created_at < $3`,
		targetID, tr.Start, tr.End).Scan(&input, &output)
	if err != nil {
		return 0, 0, apperrors.NewDatabase("summing AI token totals", err)
	}
	var in, out int64
	if input != nil {
		in = *input
	}
	if output != nil {
		out = *output
	}
	return in, out, nil
}

// AIFailureCount counts requests with no corresponding response —
// internal/service/ai only ever inserts a Request first, then a
// Response on success (see persistTaskAudit), so an orphaned request is
// exactly a failed one.
func (r *PostgresRepository) AIFailureCount(ctx context.Context, targetID uuid.UUID, tr TimeRange) (int, error) {
	return r.queryCount(ctx, `
		SELECT count(*) FROM ai_requests req
		WHERE req.target_id = $1 AND req.created_at >= $2 AND req.created_at < $3
		AND NOT EXISTS (SELECT 1 FROM ai_responses resp WHERE resp.request_id = req.id)`,
		targetID, tr.Start, tr.End)
}

// AIToolCallsByTool implements Repository.
func (r *PostgresRepository) AIToolCallsByTool(ctx context.Context, targetID uuid.UUID, tr TimeRange) ([]NamedCount, error) {
	return r.queryNamedCounts(ctx, `
		SELECT tool, count(*) FROM ai_tool_calls
		WHERE target_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY tool ORDER BY count(*) DESC`, targetID, tr.Start, tr.End)
}
