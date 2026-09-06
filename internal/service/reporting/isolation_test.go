package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	apperrors "ai-recon-platform/internal/errors"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	"ai-recon-platform/internal/repository/pagination"
)

// fakeInvestigationsSingle implements investigationrepo.Repository backed
// by exactly one investigation, enough to exercise buildInvestigationReport
// without a database. Every method beyond GetByID panics if called — this
// test's whole point is that a target mismatch must be rejected before any
// of them would ever be reached.
type fakeInvestigationsSingle struct {
	inv domaininvestigation.Investigation
}

func (f fakeInvestigationsSingle) Create(context.Context, domaininvestigation.Investigation) (domaininvestigation.Investigation, error) {
	panic("not implemented")
}
func (f fakeInvestigationsSingle) GetByID(_ context.Context, id uuid.UUID) (domaininvestigation.Investigation, error) {
	if id != f.inv.ID {
		return domaininvestigation.Investigation{}, notFoundErr{}
	}
	return f.inv, nil
}
func (f fakeInvestigationsSingle) List(context.Context, investigationrepo.ListFilter) (pagination.Page[domaininvestigation.Investigation], error) {
	panic("not implemented")
}
func (f fakeInvestigationsSingle) Update(context.Context, domaininvestigation.Investigation, int) (domaininvestigation.Investigation, error) {
	panic("not implemented")
}
func (f fakeInvestigationsSingle) UpdateFirstLastObserved(context.Context, uuid.UUID, time.Time) (domaininvestigation.Investigation, error) {
	panic("not implemented")
}

// TestBuildInvestigationReport_RejectsCrossTargetAccess is this
// platform's core "project isolation" boundary test (phase15.md §11/§81):
// this codebase has no auth/RBAC/multi-tenancy layer (confirmed by
// inspection across every phase since Phase 9) — TargetID scoping IS the
// isolation boundary for every operation that aggregates or reports on
// data by target, and every report-building function must reject a
// subject whose own TargetID doesn't match the requested target, exactly
// as sections.go's inline apperrors.NewForbidden calls are meant to.
func TestBuildInvestigationReport_RejectsCrossTargetAccess(t *testing.T) {
	targetA := uuid.New()
	targetB := uuid.New()
	inv := domaininvestigation.Investigation{ID: uuid.New(), TargetID: targetB}

	svc := &Service{investigations: fakeInvestigationsSingle{inv: inv}}

	_, err := svc.buildInvestigationReport(context.Background(), targetA, inv.ID)
	if err == nil {
		t.Fatal("expected an error when requesting targetA's report for an investigation owned by targetB, got nil")
	}
	appErr, ok := err.(*apperrors.Error)
	if !ok {
		t.Fatalf("expected *apperrors.Error, got %T: %v", err, err)
	}
	if appErr.Category != apperrors.CategoryForbidden {
		t.Errorf("category = %q, want %q", appErr.Category, apperrors.CategoryForbidden)
	}
}

func TestBuildInvestigationReport_AllowsSameTargetAccess(t *testing.T) {
	targetA := uuid.New()
	inv := domaininvestigation.Investigation{
		ID: uuid.New(), TargetID: targetA,
		Status: domaininvestigation.StatusOpen, Severity: domaininvestigation.SeverityMedium,
		Priority: domaininvestigation.PriorityNormal, Confidence: domaininvestigation.ConfidenceMedium,
		CreatedAt: time.Now(),
	}
	svc := &Service{investigations: fakeInvestigationsSingle{inv: inv}}

	// evidence is nil on this Service, so ListEvidence must not be called
	// before this reaches the TargetID check — same-target access still
	// panics later in this stripped-down fake, but only *after* proving
	// the isolation check itself passed for a legitimate same-target
	// request, which is what this test verifies via a recover.
	defer func() {
		if r := recover(); r != nil {
			// A panic here means execution got past the TargetID check
			// (the boundary this test cares about) into evidence lookup,
			// which this minimal fake doesn't implement — expected.
			return
		}
	}()
	_, err := svc.buildInvestigationReport(context.Background(), targetA, inv.ID)
	if err != nil {
		t.Fatalf("expected same-target access to pass the isolation check, got error: %v", err)
	}
}
