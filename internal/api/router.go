// Package api implements the REST resource endpoints the frontend
// (../../frontend) calls — the concrete implementation of the contract
// every frontend/src/api/*.ts module's header comment already documents.
//
// This is additive, not a rebuild: every handler here is a thin
// translation layer over already-existing internal/service/* business
// logic and internal/repository/* queries — no detection, correlation,
// investigation, intelligence, or reporting logic is duplicated or
// reimplemented. Response DTOs use camelCase JSON matching the
// frontend's TypeScript types exactly (see each file's header comment
// for which frontend src/types/*.ts file it mirrors) — a deliberate,
// separate contract from the internal Go domain structs, the same way
// frontend/src/types/*.ts is already a separate, hand-maintained mirror
// rather than a generated one.
//
// No authentication exists (see docs/security/threat-model.md T1) —
// target_id scoping remains the only boundary, exactly as it is for the
// CLI. This means this API must never be exposed on an untrusted network
// without adding authentication first; see docs/operations/deployment.md.
package api

import (
	"log/slog"
	"net/http"

	analyticssvc "ai-recon-platform/internal/analytics"
	airepo "ai-recon-platform/internal/repository/ai"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
	reportingrepo "ai-recon-platform/internal/repository/reporting"
	aisvc "ai-recon-platform/internal/service/ai"
	assetsvc "ai-recon-platform/internal/service/asset"
	correlationsvc "ai-recon-platform/internal/service/correlation"
	intelligencesvc "ai-recon-platform/internal/service/intelligence"
	investigationsvc "ai-recon-platform/internal/service/investigation"
	reportingsvc "ai-recon-platform/internal/service/reporting"
	rulesvc "ai-recon-platform/internal/service/rule"
	targetsvc "ai-recon-platform/internal/service/target"
)

// Deps is every service/repository the REST API reads from or mutates
// through — deliberately shaped to mirror internal/application.Services
// field-for-field (see that package's Services.APIDeps) without this
// package importing internal/application, so cmd/cli never pulls in an
// HTTP dependency merely by sharing internal/service/*.
type Deps struct {
	Targets        *targetsvc.Service
	Assets         *assetsvc.Service
	Findings       findingrepo.Repository
	Fingerprints   fingerprintrepo.Repository
	Rules          *rulesvc.Service
	Correlations   *correlationsvc.Service
	Investigation  *investigationsvc.Service
	Intelligence   *intelligencesvc.Service
	IntelRecords   intelrepo.RecordRepository
	AI             *aisvc.Service
	AIToolCalls    airepo.ToolCallRepository
	AIRequests     airepo.RequestRepository
	AIResponses    airepo.ResponseRepository
	Reporting      *reportingsvc.Service
	ReportPackages reportingrepo.PackageRepository
	Analytics      *analyticssvc.Service
}

// NewRouter returns an httpserver.Options.RegisterRoutes function
// registering every REST resource route onto mux.
func NewRouter(deps Deps, logger *slog.Logger) func(*http.ServeMux) {
	h := &handler{deps: deps, logger: logger}

	return func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/v1/targets", h.listTargets)
		mux.HandleFunc("GET /api/v1/targets/{id}", h.getTarget)

		mux.HandleFunc("GET /api/v1/assets", h.listAssets)
		mux.HandleFunc("GET /api/v1/assets/{id}", h.getAsset)
		mux.HandleFunc("GET /api/v1/assets/{id}/fingerprints", h.getAssetFingerprints)
		mux.HandleFunc("GET /api/v1/assets/{id}/findings", h.getAssetFindings)

		mux.HandleFunc("GET /api/v1/findings", h.listFindings)
		mux.HandleFunc("GET /api/v1/findings/{id}", h.getFinding)

		mux.HandleFunc("GET /api/v1/rules", h.listRules)
		mux.HandleFunc("GET /api/v1/rules/{id}", h.getRule)
		mux.HandleFunc("GET /api/v1/detection-matches", h.listDetectionMatches)

		mux.HandleFunc("GET /api/v1/alerts", h.listAlerts)
		mux.HandleFunc("PATCH /api/v1/alerts/{id}", h.patchAlert)

		mux.HandleFunc("GET /api/v1/investigations", h.listInvestigations)
		mux.HandleFunc("GET /api/v1/investigations/{id}", h.getInvestigation)
		mux.HandleFunc("GET /api/v1/investigations/{id}/timeline", h.getInvestigationTimeline)
		mux.HandleFunc("GET /api/v1/investigations/{id}/notes", h.getInvestigationNotes)
		mux.HandleFunc("GET /api/v1/investigations/{id}/hypotheses", h.getInvestigationHypotheses)

		mux.HandleFunc("GET /api/v1/incident-clusters", h.listIncidentClusters)
		mux.HandleFunc("GET /api/v1/incident-clusters/{id}", h.getIncidentCluster)

		mux.HandleFunc("GET /api/v1/correlations", h.listCorrelations)
		mux.HandleFunc("GET /api/v1/correlations/{id}", h.getCorrelation)
		mux.HandleFunc("GET /api/v1/correlations/{id}/graph", h.getCorrelationGraph)
		mux.HandleFunc("GET /api/v1/attack-chains", h.listAttackChains)
		mux.HandleFunc("GET /api/v1/attack-chains/{id}", h.getAttackChain)
		mux.HandleFunc("GET /api/v1/attack-chains/{id}/stages", h.getAttackChainStages)

		mux.HandleFunc("GET /api/v1/intelligence", h.listIntelligence)
		mux.HandleFunc("GET /api/v1/risk-scores", h.listRiskScores)

		mux.HandleFunc("GET /api/v1/analytics/overview", h.analyticsOverview)
		mux.HandleFunc("GET /api/v1/analytics/risk", h.analyticsRisk)
		mux.HandleFunc("GET /api/v1/analytics/alerts", h.analyticsAlerts)
		mux.HandleFunc("GET /api/v1/analytics/detections", h.analyticsDetections)
		mux.HandleFunc("GET /api/v1/analytics/findings", h.analyticsFindings)
		mux.HandleFunc("GET /api/v1/analytics/assets", h.analyticsAssets)
		mux.HandleFunc("GET /api/v1/analytics/attack-surface", h.analyticsAttackSurface)
		mux.HandleFunc("GET /api/v1/analytics/correlations", h.analyticsCorrelations)
		mux.HandleFunc("GET /api/v1/analytics/investigations", h.analyticsInvestigations)
		mux.HandleFunc("GET /api/v1/analytics/intelligence", h.analyticsIntelligence)
		mux.HandleFunc("GET /api/v1/analytics/ai", h.analyticsAI)
		mux.HandleFunc("GET /api/v1/analytics/posture", h.analyticsPosture)

		mux.HandleFunc("GET /api/v1/ai/sessions", h.listAISessions)
		mux.HandleFunc("GET /api/v1/ai/sessions/{id}", h.getAISession)
		mux.HandleFunc("GET /api/v1/ai/sessions/{id}/messages", h.getSessionMessages)
		mux.HandleFunc("POST /api/v1/ai/sessions/{id}/messages", h.postSessionMessage)
		mux.HandleFunc("GET /api/v1/ai/sessions/{id}/tool-calls", h.getSessionToolCalls)
		mux.HandleFunc("GET /api/v1/ai/sessions/{id}/result", h.getSessionResult)

		mux.HandleFunc("GET /api/v1/reports", h.listReports)
		mux.HandleFunc("GET /api/v1/reports/{id}", h.getReport)
		mux.HandleFunc("GET /api/v1/evidence-packages", h.listEvidencePackages)
		mux.HandleFunc("GET /api/v1/controls", h.listControlEvidence)

		mux.HandleFunc("GET /api/v1/technologies", h.listTechnologies)
		mux.HandleFunc("GET /api/v1/audit", h.listAuditEvents)
		mux.HandleFunc("GET /api/v1/search", h.search)
	}
}

type handler struct {
	deps   Deps
	logger *slog.Logger
}
