package rule

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	domainrule "ai-recon-platform/internal/domain/rule"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/ruleengine"
)

// roleFor names the evidence role every event in a match should be
// attached with, based on the rule's type (phase11.md §63).
func roleFor(ruleType ruleengine.Type) domainrule.EvidenceRole {
	switch ruleType {
	case ruleengine.TypeSequence:
		return domainrule.RoleSequenceStep
	case ruleengine.TypeAggregation:
		return domainrule.RoleSupporting
	default: // field_match, threshold
		return domainrule.RoleTrigger
	}
}

func toSourceType(t ruleengine.EventType) domainrule.SourceType { return domainrule.SourceType(t) }

// fingerprintGroupKey returns the group key ComputeFingerprint should
// use — the match's own GroupKey for threshold/aggregation/sequence
// rules, or (since TypeFieldMatch has no grouping at all) a
// synthetic key derived from the triggering event's own identity, so
// distinct events never collapse into the same fingerprint
// (phase11.md §33 — the fingerprint must distinguish genuinely distinct
// occurrences, not merge them).
func fingerprintGroupKey(ruleType ruleengine.Type, m ruleengine.Match) map[string]string {
	if ruleType != ruleengine.TypeFieldMatch {
		return m.GroupKey
	}
	key := map[string]string{}
	if len(m.Events) > 0 {
		key["event.source_id"] = m.Events[0].SourceID.String()
	}
	return key
}

// EvaluateResult is one Evaluate call's outcome.
type EvaluateResult struct {
	Rule             domainrule.Rule
	Version          domainrule.Version
	EventsConsidered int
	Matches          []domainrule.DetectionMatch
	Alerts           []domainrule.Alert
	Duration         time.Duration
	DryRun           bool
}

// Evaluate runs ruleID's latest ENABLED version against events observed
// within [from, to) (phase11.md §14/§57). Unless dryRun, every resulting
// Match is persisted (deduplicated by fingerprint), its evidence
// attached, active suppressions applied, and a corresponding Alert
// upserted (phase11.md §16/§17/§20/§34/§35). A disabled rule (or one
// with no enabled version) is rejected — no new matches are ever
// produced for it (phase11.md §31).
func (s *Service) Evaluate(ctx context.Context, ruleID uuid.UUID, from, to time.Time, dryRun bool) (EvaluateResult, error) {
	start := time.Now()

	r, err := s.rules.GetRuleByID(ctx, ruleID)
	if err != nil {
		return EvaluateResult{}, err
	}
	if !r.Status.Active() {
		return EvaluateResult{}, apperrors.NewValidation(fmt.Sprintf("rule %q is not enabled (status: %s) — enable it before evaluating", r.Name, r.Status), nil)
	}
	if to.Sub(from) > s.cfg.EffectiveHistoricalMaxRange() {
		return EvaluateResult{}, apperrors.NewValidation(
			fmt.Sprintf("requested range %s exceeds the maximum historical evaluation range %s without an explicit --backfill", to.Sub(from), s.cfg.EffectiveHistoricalMaxRange()), nil)
	}

	version, err := s.versions.GetLatestEnabled(ctx, ruleID)
	if err != nil {
		return EvaluateResult{}, err
	}
	def, err := ruleengine.ParseJSON([]byte(version.Definition))
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("parsing persisted rule definition: %w", err)
	}
	compiled, err := ruleengine.Compile(def)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("compiling persisted rule definition: %w", err)
	}

	events, err := s.buildEvents(ctx, r.TargetID, from, to)
	if err != nil {
		return EvaluateResult{}, err
	}

	engineMatches, err := s.engine.Evaluate(ctx, compiled, events)
	if err != nil {
		return EvaluateResult{}, err
	}

	result := EvaluateResult{Rule: r, Version: version, EventsConsidered: len(events), DryRun: dryRun}
	if dryRun {
		result.Duration = time.Since(start)
		return result, nil
	}

	ruleSuppressed, err := s.hasActiveSuppression(ctx, domainrule.ScopeRule, r.ID)
	if err != nil {
		s.logger.Error("rule_suppression_check_failed", "rule_id", r.ID, "error", err)
	}

	for _, m := range engineMatches {
		windowDuration := aggregationWindow(def)
		fp := ruleengine.ComputeFingerprint(r.ID, version.Version, fingerprintGroupKey(def.RuleType, m), m.WindowStart, windowDuration)
		explanation := ruleengine.Explain(r.Name, def, m)

		status := domainrule.MatchOpen
		if ruleSuppressed {
			status = domainrule.MatchSuppressed
		}

		domainMatch := domainrule.DetectionMatch{
			TargetID: r.TargetID, RuleID: r.ID, RuleVersion: version.Version, Fingerprint: fp,
			FirstObservedAt: m.FirstObserved(), LastObservedAt: m.LastObserved(),
			Severity: domainrule.Severity(m.Severity), Confidence: domainrule.Confidence(m.Confidence),
			Status: status, Explanation: explanation,
		}
		saved, created, err := s.matches.UpsertMatch(ctx, domainMatch)
		if err != nil {
			s.logger.Error("detection_match_persist_failed", "rule_id", r.ID, "fingerprint", fp, "error", err)
			continue
		}
		result.Matches = append(result.Matches, saved)

		role := roleFor(def.RuleType)
		for _, evt := range m.Events {
			_, _, err := s.evidence.AttachEvidence(ctx, domainrule.MatchEvidence{
				DetectionMatchID: saved.ID, SourceType: toSourceType(evt.Type), SourceID: evt.SourceID, Role: role, ObservedAt: evt.Timestamp,
			})
			if err != nil {
				s.logger.Error("detection_evidence_attach_failed", "match_id", saved.ID, "error", err)
			}
		}

		if !created && saved.Status != domainrule.MatchOpen {
			// An analyst already acknowledged/resolved/suppressed this
			// match (or a prior evaluation marked it rule-suppressed) —
			// never re-open it by re-upserting an alert for it.
			continue
		}
		if ruleSuppressed {
			continue
		}
		matchSuppressed, err := s.hasActiveSuppression(ctx, domainrule.ScopeMatch, saved.ID)
		if err != nil {
			s.logger.Error("match_suppression_check_failed", "match_id", saved.ID, "error", err)
		}
		if matchSuppressed {
			if _, err := s.matches.UpdateMatchStatus(ctx, saved.ID, domainrule.MatchSuppressed); err != nil {
				s.logger.Error("detection_match_suppress_failed", "match_id", saved.ID, "error", err)
			}
			continue
		}

		alert := domainrule.Alert{
			TargetID: r.TargetID, DetectionMatchID: saved.ID, Title: alertTitle(r.Name, m),
			Description: explanation, Severity: domainrule.Severity(m.Severity), Confidence: domainrule.Confidence(m.Confidence),
			Status: domainrule.AlertOpen, FirstObservedAt: saved.FirstObservedAt, LastObservedAt: saved.LastObservedAt,
		}
		savedAlert, _, err := s.alerts.UpsertAlert(ctx, alert)
		if err != nil {
			s.logger.Error("alert_persist_failed", "match_id", saved.ID, "error", err)
			continue
		}
		result.Alerts = append(result.Alerts, savedAlert)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func alertTitle(ruleName string, m ruleengine.Match) string {
	if len(m.GroupKey) == 0 {
		return fmt.Sprintf("%s (%d event(s))", ruleName, len(m.Events))
	}
	return fmt.Sprintf("%s — %d event(s)", ruleName, len(m.Events))
}

func aggregationWindow(def ruleengine.Definition) time.Duration {
	switch {
	case def.Aggregation != nil:
		return def.Aggregation.Window
	case def.Sequence != nil:
		return def.Sequence.Window
	default:
		return 0
	}
}

func (s *Service) hasActiveSuppression(ctx context.Context, scope domainrule.SuppressionScope, scopeID uuid.UUID) (bool, error) {
	active, err := s.suppressions.ActiveFor(ctx, scope, scopeID, time.Now().UTC())
	if err != nil {
		return false, err
	}
	return len(active) > 0, nil
}
