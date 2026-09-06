package reporting

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/analytics"
	domainintel "ai-recon-platform/internal/domain/intelligence"
	apperrors "ai-recon-platform/internal/errors"
	rept "ai-recon-platform/internal/reporting"
	findingrepo "ai-recon-platform/internal/repository/finding"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	"ai-recon-platform/internal/repository/pagination"
)

// buildResult is what every per-type section builder returns: the
// report's rendered content, its title, and the full evidence-reference
// list every citation in Sections must be drawn from (phase14.md §37).
type buildResult struct {
	Title    string
	Sections rept.Sections
	Refs     []rept.EvidenceRef
}

func ref(kind, id string, ts time.Time) rept.EvidenceRef {
	return rept.EvidenceRef{Type: kind, ID: id, Timestamp: ts}
}

// ---------------------------------------------------------------------
// investigation report (phase14.md §33)
// ---------------------------------------------------------------------

func (s *Service) buildInvestigationReport(ctx context.Context, targetID, investigationID uuid.UUID) (buildResult, error) {
	inv, err := s.investigations.GetByID(ctx, investigationID)
	if err != nil {
		return buildResult{}, err
	}
	if inv.TargetID != targetID {
		return buildResult{}, apperrors.NewForbidden("investigation does not belong to this target", nil)
	}

	var refs []rept.EvidenceRef
	invRef := ref("investigation", inv.ID.String(), inv.CreatedAt)
	refs = append(refs, invRef)

	summary := fmt.Sprintf("Status: %s | Severity: %s | Priority: %s | Confidence: %s\nCreated: %s",
		inv.Status, inv.Severity, inv.Priority, inv.Confidence, inv.CreatedAt.Format(time.RFC3339))
	if inv.ClosedAt != nil {
		summary += fmt.Sprintf("\nClosed: %s (duration: %s)", inv.ClosedAt.Format(time.RFC3339), inv.ClosedAt.Sub(inv.CreatedAt))
	}

	evidencePage, _ := s.evidence.ListEvidence(ctx, investigationrepo.EvidenceListFilter{
		InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit},
	})
	var scopeLines []string
	for _, ev := range evidencePage.Items {
		scopeLines = append(scopeLines, fmt.Sprintf("- %s %s", ev.SourceType, ev.SourceID))
		refs = append(refs, ref(string(ev.SourceType), ev.SourceID.String(), ev.ObservedAt))
	}

	timelinePage, _ := s.timeline.ListTimeline(ctx, investigationrepo.TimelineListFilter{
		InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit},
	})
	var timelineLines []string
	for _, e := range timelinePage.Items {
		timelineLines = append(timelineLines, fmt.Sprintf("%s  %s  %s", e.Timestamp.Format(time.RFC3339), e.Type, e.Title))
	}

	sections := rept.Sections{
		{Title: "Executive Summary", Body: fmt.Sprintf("Investigation %q. %s", inv.Title, summary), Citations: []string{invRef.Token()}},
		{Title: "Scope", Body: joinOrNone(scopeLines, "No evidence has been attached to this investigation.")},
		{Title: "Timeline", Body: joinOrNone(timelineLines, "No timeline events recorded.")},
		{Title: "Evidence Gaps", Body: "See `ai-recon ai report` for an AI-assisted evidence-gap analysis of this investigation — not duplicated here."},
		{Title: "Analyst Conclusions", Body: "Pending analyst review — this section is intentionally left for manual completion before approval."},
		{Title: "Recommendations", Body: "Pending analyst review."},
	}
	return buildResult{Title: "Investigation Report: " + inv.Title, Sections: sections, Refs: refs}, nil
}

// ---------------------------------------------------------------------
// asset report (phase14.md — asset risk view, §29)
// ---------------------------------------------------------------------

func (s *Service) buildAssetReport(ctx context.Context, targetID, assetID uuid.UUID) (buildResult, error) {
	a, err := s.assets.GetByID(ctx, assetID)
	if err != nil {
		return buildResult{}, err
	}
	if a.TargetID != targetID {
		return buildResult{}, apperrors.NewForbidden("asset does not belong to this target", nil)
	}
	assetRef := ref("asset", a.ID.String(), a.LastSeen)

	identity := a.IdentityKey
	if a.Hostname != nil && *a.Hostname != "" {
		identity = *a.Hostname
	}
	summary := fmt.Sprintf("Type: %s | Status: %s | First seen: %s | Last seen: %s",
		a.Type, a.Status, a.FirstSeen.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339))

	findingsPage, _ := s.findings.List(ctx, findingrepo.ListFilter{TargetID: targetID, AssetID: assetID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	var findingLines []string
	refs := []rept.EvidenceRef{assetRef}
	for _, f := range findingsPage.Items {
		findingLines = append(findingLines, fmt.Sprintf("- [%s] %s (%s)", f.Severity, f.Title, f.Status))
		refs = append(refs, ref("finding", f.ID.String(), f.LastSeen))
	}

	riskLine := "No risk score has been calculated for this asset."
	if score, err := s.risk.GetLatestRiskScore(ctx, domainintel.EntityAsset, assetID); err == nil {
		riskLine = fmt.Sprintf("Score: %d | Severity: %s | Model: %s | Calculated: %s", score.Score, score.Severity, score.ModelVersion, score.CalculatedAt.Format(time.RFC3339))
		refs = append(refs, ref("asset", assetID.String(), score.CalculatedAt))
	}

	sections := rept.Sections{
		{Title: "Asset Identity", Body: identity + "\n" + summary, Citations: []string{assetRef.Token()}},
		{Title: "Findings", Body: joinOrNone(findingLines, "No findings recorded for this asset.")},
		{Title: "Risk History", Body: riskLine},
	}
	return buildResult{Title: "Asset Report: " + identity, Sections: sections, Refs: refs}, nil
}

// ---------------------------------------------------------------------
// correlation report (phase14.md §37's "correlation" reference list)
// ---------------------------------------------------------------------

func (s *Service) buildCorrelationReport(ctx context.Context, targetID, correlationID uuid.UUID) (buildResult, error) {
	c, err := s.correlations.GetCorrelationByID(ctx, correlationID)
	if err != nil {
		return buildResult{}, err
	}
	if c.TargetID != targetID {
		return buildResult{}, apperrors.NewForbidden("correlation does not belong to this target", nil)
	}
	corrRef := ref("correlation", c.ID.String(), c.LastObservedAt)
	refs := []rept.EvidenceRef{corrRef}

	summary := fmt.Sprintf("%s\nStatus: %s | Severity: %s | Confidence: %s | Score: %d",
		c.Description, c.Status, c.Severity, c.Confidence, c.Score)

	nodes, _ := s.nodes.ListNodes(ctx, correlationID)
	var nodeLines []string
	for _, n := range nodes {
		nodeLines = append(nodeLines, fmt.Sprintf("- %s %s (%s)", n.Type, n.ReferenceID, n.Role))
		refs = append(refs, ref(string(n.Type), n.ReferenceID.String(), n.Timestamp))
	}

	chainLine := "No attack chain was generated for this correlation."
	if chain, err := s.chains.GetChainByCorrelationID(ctx, correlationID); err == nil {
		stages, _ := s.stages.ListStages(ctx, chain.ID)
		chainLine = fmt.Sprintf("%s (%d stage(s), confidence %s)", chain.Name, len(stages), chain.Confidence)
		for _, st := range stages {
			chainLine += fmt.Sprintf("\n  %d. %s (%s)", st.Order, st.Stage, st.Confidence)
		}
	}

	sections := rept.Sections{
		{Title: "Executive Summary", Body: summary, Citations: []string{corrRef.Token()}},
		{Title: "Correlated Evidence", Body: joinOrNone(nodeLines, "No evidence nodes recorded.")},
		{Title: "Attack Chain", Body: chainLine},
	}
	return buildResult{Title: "Correlation Report", Sections: sections, Refs: refs}, nil
}

// ---------------------------------------------------------------------
// detection report — target-wide (phase14.md §30)
// ---------------------------------------------------------------------

func (s *Service) buildDetectionReport(ctx context.Context, targetID uuid.UUID, r analytics.TimeRange) (buildResult, error) {
	d, err := s.analytics.Detections(ctx, targetID, r)
	if err != nil {
		return buildResult{}, err
	}
	summary := fmt.Sprintf("Enabled rules: %d | Disabled rules: %d", d.EnabledRules, d.DisabledRules)
	var noisy []string
	for i, rr := range d.NoisyRules {
		if i >= 10 {
			break
		}
		noisy = append(noisy, fmt.Sprintf("- %s: %d matches, %.0f%% alert conversion, %.0f%% dismissal rate", rr.Rule, rr.Matches, rr.AlertConversion*100, rr.DismissalRate*100))
	}
	sections := rept.Sections{
		{Title: "Rule Inventory", Body: summary},
		{Title: "Noisiest Rules", Body: joinOrNone(noisy, "No detection matches in this range.")},
	}
	return buildResult{Title: "Detection Engineering Report", Sections: sections}, nil
}

// ---------------------------------------------------------------------
// attack-surface report — target-wide (phase14.md §35)
// ---------------------------------------------------------------------

func (s *Service) buildAttackSurfaceReport(ctx context.Context, targetID uuid.UUID, r analytics.TimeRange) (buildResult, error) {
	trend, err := s.analytics.AttackSurface(ctx, targetID, r)
	if err != nil {
		return buildResult{}, err
	}
	assetStats, err := s.analytics.Assets(ctx, targetID)
	if err != nil {
		return buildResult{}, err
	}
	var byType []string
	for _, t := range trend.ByType {
		byType = append(byType, fmt.Sprintf("- %s: %d", t.Name, t.Count))
	}
	sections := rept.Sections{
		{Title: "Asset Inventory", Body: fmt.Sprintf("Total assets: %d\nCritical risk: %d | High risk: %d", assetStats.Total, assetStats.RiskCritical, assetStats.RiskHigh)},
		{Title: "Composition", Body: joinOrNone(byType, "No assets recorded.")},
		{Title: "Changes", Body: fmt.Sprintf("Removed/retired assets in range: %d", trend.RemovedAssets)},
	}
	return buildResult{Title: "Attack Surface Report", Sections: sections}, nil
}

// ---------------------------------------------------------------------
// executive report — target-wide, concise (phase14.md §36)
// ---------------------------------------------------------------------

func (s *Service) buildExecutiveReport(ctx context.Context, targetID uuid.UUID, r analytics.TimeRange) (buildResult, error) {
	overview, err := s.analytics.Overview(ctx, targetID)
	if err != nil {
		return buildResult{}, err
	}
	posture, err := s.analytics.Posture(ctx, targetID)
	if err != nil {
		return buildResult{}, err
	}
	riskTrend, err := s.analytics.Risk(ctx, targetID, r)
	if err != nil {
		return buildResult{}, err
	}
	surface, err := s.analytics.AttackSurface(ctx, targetID, r)
	if err != nil {
		return buildResult{}, err
	}

	postureLine := "insufficient data to calculate a security posture score"
	if posture.ScoredEntities > 0 {
		postureLine = fmt.Sprintf("%.0f/100 (from %d scored entities) — see docs/analytics/metrics.md for how this is calculated; not an objective measure of security", posture.Score, posture.ScoredEntities)
	}

	sections := rept.Sections{
		{Title: "Security Posture", Body: postureLine},
		{Title: "Risk Trend", Body: fmt.Sprintf("%d risk data point(s) in range; %d critical, %d high risk asset(s) currently", len(riskTrend.Trend), overview.CriticalRiskAssets, overview.HighRiskAssets)},
		{Title: "Critical Findings & Assets", Body: fmt.Sprintf("Open findings: %d | Open alerts: %d | Critical risk assets: %d", overview.OpenFindings, overview.OpenAlerts, overview.CriticalRiskAssets)},
		{Title: "Incident Trend", Body: fmt.Sprintf("Active investigations: %d", overview.ActiveInvestigations)},
		{Title: "Attack Surface Changes", Body: fmt.Sprintf("Removed/retired assets in range: %d", surface.RemovedAssets)},
		{Title: "Major Correlations", Body: fmt.Sprintf("Open correlations: %d", overview.OpenCorrelations)},
		{Title: "Key Recommendations", Body: "Review open critical/high risk assets and active investigations listed above; see the corresponding detailed reports for evidence-backed detail."},
	}
	return buildResult{Title: "Executive Security Report", Sections: sections}, nil
}

// ---------------------------------------------------------------------
// audit report — target-wide (phase14.md §48), reusing the investigation
// timeline as this platform's existing audit log (the same "these ARE
// the audit trail" precedent phase9.md/phase11.md/phase13.md already
// established) rather than a new audit table.
// ---------------------------------------------------------------------

func (s *Service) buildAuditReport(ctx context.Context, targetID uuid.UUID, r analytics.TimeRange) (buildResult, error) {
	invPage, err := s.investigations.List(ctx, investigationrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		return buildResult{}, err
	}
	var lines []string
	for _, inv := range invPage.Items {
		page, err := s.timeline.ListTimeline(ctx, investigationrepo.TimelineListFilter{InvestigationID: inv.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
		if err != nil {
			continue
		}
		for _, e := range page.Items {
			if e.Timestamp.Before(r.Start) || !e.Timestamp.Before(r.End) {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s  actor=%s  action=%s  resource=investigation:%s  %q",
				e.Timestamp.Format(time.RFC3339), orUnknown(e.Actor), e.Type, inv.ID, e.Title))
		}
	}
	sections := rept.Sections{
		{Title: "Audit Trail", Body: joinOrNone(lines, "No audited activity in this range.")},
	}
	return buildResult{Title: "Audit Report", Sections: sections}, nil
}

func joinOrNone(lines []string, none string) string {
	if len(lines) == 0 {
		return none
	}
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "system"
	}
	return s
}
