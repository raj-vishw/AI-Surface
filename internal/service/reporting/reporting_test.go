package reporting

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	domainreporting "ai-recon-platform/internal/domain/reporting"
	rept "ai-recon-platform/internal/reporting"
	"ai-recon-platform/internal/repository/pagination"
	reportingrepo "ai-recon-platform/internal/repository/reporting"
)

// --- fakes for the 4 reportingrepo interfaces ------------------------

type fakeReports struct {
	byID map[uuid.UUID]domainreporting.Report
}

func newFakeReports() *fakeReports { return &fakeReports{byID: map[uuid.UUID]domainreporting.Report{}} }

func (f *fakeReports) CreateReport(_ context.Context, r domainreporting.Report) (domainreporting.Report, error) {
	r.ID = uuid.New()
	r.CreatedAt = time.Now()
	r.GeneratedAt = time.Now()
	f.byID[r.ID] = r
	return r, nil
}
func (f *fakeReports) GetReportByID(_ context.Context, id uuid.UUID) (domainreporting.Report, error) {
	r, ok := f.byID[id]
	if !ok {
		return domainreporting.Report{}, notFoundErr{}
	}
	return r, nil
}
func (f *fakeReports) ListReports(_ context.Context, filter reportingrepo.ReportListFilter) (pagination.Page[domainreporting.Report], error) {
	var items []domainreporting.Report
	for _, r := range f.byID {
		if filter.TargetID != uuid.Nil && r.TargetID != filter.TargetID {
			continue
		}
		items = append(items, r)
	}
	return pagination.Page[domainreporting.Report]{Items: items}, nil
}
func (f *fakeReports) LatestVersion(_ context.Context, targetID uuid.UUID, reportType domainreporting.Type, subjectID *uuid.UUID) (int, error) {
	max := 0
	for _, r := range f.byID {
		if r.TargetID != targetID || r.ReportType != reportType {
			continue
		}
		sameSubject := (r.SubjectID == nil && subjectID == nil) || (r.SubjectID != nil && subjectID != nil && *r.SubjectID == *subjectID)
		if !sameSubject {
			continue
		}
		if r.Version > max {
			max = r.Version
		}
	}
	return max, nil
}
func (f *fakeReports) Approve(_ context.Context, id uuid.UUID, approvedBy, notes string) (domainreporting.Report, error) {
	r, ok := f.byID[id]
	if !ok {
		return domainreporting.Report{}, notFoundErr{}
	}
	r.Status = domainreporting.StatusApproved
	r.ApprovedBy = &approvedBy
	now := time.Now()
	r.ApprovedAt = &now
	r.ApprovalNotes = notes
	f.byID[id] = r
	return r, nil
}
func (f *fakeReports) SetStatus(_ context.Context, id uuid.UUID, status domainreporting.Status) (domainreporting.Report, error) {
	r, ok := f.byID[id]
	if !ok {
		return domainreporting.Report{}, notFoundErr{}
	}
	r.Status = status
	f.byID[id] = r
	return r, nil
}

type notFoundErr struct{}

func (notFoundErr) Error() string { return "not found" }

type fakePackages struct {
	byID map[uuid.UUID]domainreporting.Package
}

func newFakePackages() *fakePackages {
	return &fakePackages{byID: map[uuid.UUID]domainreporting.Package{}}
}
func (f *fakePackages) CreatePackage(_ context.Context, p domainreporting.Package) (domainreporting.Package, error) {
	p.ID = uuid.New()
	p.CreatedAt = time.Now()
	f.byID[p.ID] = p
	return p, nil
}
func (f *fakePackages) GetPackageByID(_ context.Context, id uuid.UUID) (domainreporting.Package, error) {
	p, ok := f.byID[id]
	if !ok {
		return domainreporting.Package{}, notFoundErr{}
	}
	return p, nil
}
func (f *fakePackages) ListPackages(context.Context, reportingrepo.PackageListFilter) (pagination.Page[domainreporting.Package], error) {
	return pagination.Page[domainreporting.Package]{}, nil
}

type fakeItems struct {
	byPackage map[uuid.UUID][]domainreporting.Item
}

func newFakeItems() *fakeItems { return &fakeItems{byPackage: map[uuid.UUID][]domainreporting.Item{}} }
func (f *fakeItems) CreateItems(_ context.Context, items []domainreporting.Item) ([]domainreporting.Item, error) {
	out := make([]domainreporting.Item, 0, len(items))
	for _, item := range items {
		item.ID = uuid.New()
		item.CreatedAt = time.Now()
		f.byPackage[item.PackageID] = append(f.byPackage[item.PackageID], item)
		out = append(out, item)
	}
	return out, nil
}
func (f *fakeItems) ListItemsByPackage(_ context.Context, packageID uuid.UUID) ([]domainreporting.Item, error) {
	return f.byPackage[packageID], nil
}

type fakeControls struct {
	rows []domainreporting.ControlEvidence
}

func (f *fakeControls) RecordControlEvidence(_ context.Context, c domainreporting.ControlEvidence) (domainreporting.ControlEvidence, error) {
	c.ID = uuid.New()
	c.CreatedAt = time.Now()
	f.rows = append(f.rows, c)
	return c, nil
}
func (f *fakeControls) ListControlEvidence(_ context.Context, filter reportingrepo.ControlEvidenceListFilter) (pagination.Page[domainreporting.ControlEvidence], error) {
	var items []domainreporting.ControlEvidence
	for _, c := range f.rows {
		if filter.ControlID != "" && c.ControlID != filter.ControlID {
			continue
		}
		items = append(items, c)
	}
	return pagination.Page[domainreporting.ControlEvidence]{Items: items}, nil
}
func (f *fakeControls) DistinctControls(context.Context, uuid.UUID) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, c := range f.rows {
		if !seen[c.ControlID] {
			seen[c.ControlID] = true
			out = append(out, c.ControlID)
		}
	}
	return out, nil
}

func newTestService(reports *fakeReports, packages *fakePackages, items *fakeItems, controls *fakeControls) *Service {
	return &Service{reports: reports, packages: packages, items: items, controls: controls}
}

// --- tests -------------------------------------------------------------

func makeStoredReport(t *testing.T, reports *fakeReports, targetID uuid.UUID, sections rept.Sections, refs []rept.EvidenceRef) domainreporting.Report {
	t.Helper()
	envelope := rept.Envelope{
		Metadata: rept.Metadata{ReportType: "executive", TargetID: targetID.String(), GeneratedBy: "analyst1", Status: "generated"},
		Data:     sections, EvidenceReferences: sections.AllCitations(), Refs: refs,
	}
	content, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	r := domainreporting.Report{
		TargetID: targetID, ReportType: domainreporting.TypeExecutive, Version: 1,
		Title: "Test Report", Content: string(content), Status: domainreporting.StatusGenerated,
		ContentHash: rept.ContentHash(string(content)), GeneratedBy: "analyst1",
	}
	saved, err := reports.CreateReport(context.Background(), r)
	if err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
	return saved
}

func TestApprove_RequiresActor(t *testing.T) {
	reports := newFakeReports()
	svc := newTestService(reports, nil, nil, nil)
	report := makeStoredReport(t, reports, uuid.New(), nil, nil)

	if _, err := svc.Approve(context.Background(), report.ID, "", ""); err == nil {
		t.Fatal("expected an error when approvedBy is empty")
	}
}

func TestApprove_RejectsDoubleApproval(t *testing.T) {
	reports := newFakeReports()
	svc := newTestService(reports, nil, nil, nil)
	report := makeStoredReport(t, reports, uuid.New(), nil, nil)

	if _, err := svc.Approve(context.Background(), report.ID, "analyst1", "looks good"); err != nil {
		t.Fatalf("first Approve: %v", err)
	}
	if _, err := svc.Approve(context.Background(), report.ID, "analyst2", "again"); err == nil {
		t.Fatal("expected an error approving an already-approved report")
	}
}

func TestApprove_RecordsActorAndTimestamp(t *testing.T) {
	reports := newFakeReports()
	svc := newTestService(reports, nil, nil, nil)
	report := makeStoredReport(t, reports, uuid.New(), nil, nil)

	approved, err := svc.Approve(context.Background(), report.ID, "analyst1", "reviewed thoroughly")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approved.ApprovedBy == nil || *approved.ApprovedBy != "analyst1" {
		t.Errorf("ApprovedBy = %v, want analyst1", approved.ApprovedBy)
	}
	if approved.ApprovedAt == nil {
		t.Error("ApprovedAt was not set")
	}
	if approved.ApprovalNotes != "reviewed thoroughly" {
		t.Errorf("ApprovalNotes = %q", approved.ApprovalNotes)
	}
	if approved.Status != domainreporting.StatusApproved {
		t.Errorf("Status = %s, want approved", approved.Status)
	}
}

func TestExport_JSON_RedactsSecretsAndEscapesHTML(t *testing.T) {
	reports := newFakeReports()
	svc := newTestService(reports, nil, nil, nil)
	sections := rept.Sections{{Title: "Findings", Body: "Leaked password=hunter2 and <script>alert(1)</script>"}}
	report := makeStoredReport(t, reports, uuid.New(), sections, nil)

	out, err := svc.Export(context.Background(), report.ID, "json")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "hunter2") {
		t.Errorf("exported JSON leaked a secret: %s", s)
	}
	if strings.Contains(s, "<script>") {
		t.Errorf("exported JSON contains a raw script tag: %s", s)
	}
}

func TestExport_CSV_EscapesInjectionAndSecrets(t *testing.T) {
	reports := newFakeReports()
	svc := newTestService(reports, nil, nil, nil)
	sections := rept.Sections{{Title: "=cmd|'/c calc'!A1", Body: "api_key: abcdef0123456789"}}
	report := makeStoredReport(t, reports, uuid.New(), sections, nil)

	out, err := svc.Export(context.Background(), report.ID, "csv")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "abcdef0123456789") {
		t.Errorf("exported CSV leaked a secret: %s", s)
	}
	if !strings.Contains(s, "'=cmd") {
		t.Errorf("exported CSV did not escape a formula-injection title: %s", s)
	}
}

func TestExport_RejectsUnsupportedFormat(t *testing.T) {
	reports := newFakeReports()
	svc := newTestService(reports, nil, nil, nil)
	report := makeStoredReport(t, reports, uuid.New(), nil, nil)
	if _, err := svc.Export(context.Background(), report.ID, "xml"); err == nil {
		t.Fatal("expected an error for an unsupported export format")
	}
}

func TestCreateEvidencePackage_ProducesHashedManifest(t *testing.T) {
	reports := newFakeReports()
	packages := newFakePackages()
	items := newFakeItems()
	svc := newTestService(reports, packages, items, nil)

	targetID := uuid.New()
	findingID := uuid.New()
	refs := []rept.EvidenceRef{{Type: "finding", ID: findingID.String(), Timestamp: time.Now()}}
	report := makeStoredReport(t, reports, targetID, rept.Sections{{Title: "x", Body: "y"}}, refs)

	pkg, manifest, err := svc.CreateEvidencePackage(context.Background(), report.ID, "analyst1")
	if err != nil {
		t.Fatalf("CreateEvidencePackage: %v", err)
	}
	if pkg.CreatedBy != "analyst1" {
		t.Errorf("CreatedBy = %q", pkg.CreatedBy)
	}
	if len(manifest) != 1 {
		t.Fatalf("len(manifest) = %d, want 1", len(manifest))
	}
	if manifest[0].Hash == "" {
		t.Error("manifest item has no hash")
	}
	if manifest[0].ReferenceID != findingID {
		t.Errorf("ReferenceID = %s, want %s", manifest[0].ReferenceID, findingID)
	}
}

func TestCreateEvidencePackage_RequiresActor(t *testing.T) {
	reports := newFakeReports()
	svc := newTestService(reports, newFakePackages(), newFakeItems(), nil)
	report := makeStoredReport(t, reports, uuid.New(), nil, nil)
	if _, _, err := svc.CreateEvidencePackage(context.Background(), report.ID, ""); err == nil {
		t.Fatal("expected an error when actor is empty")
	}
}

func TestControlDashboard_ReportsGapsByAbsence(t *testing.T) {
	controls := &fakeControls{}
	svc := newTestService(nil, nil, nil, controls)
	targetID := uuid.New()

	if _, err := svc.RecordControlEvidence(context.Background(), domainreporting.ControlEvidence{
		TargetID: targetID, ControlID: "AC-2", EvidenceType: domainreporting.EvidenceFinding,
		ReferenceID: uuid.New(), Description: "x", CollectedAt: time.Now(),
	}); err != nil {
		t.Fatalf("RecordControlEvidence: %v", err)
	}

	dashboard, err := svc.ControlDashboard(context.Background(), targetID)
	if err != nil {
		t.Fatalf("ControlDashboard: %v", err)
	}
	if len(dashboard) != 1 || dashboard[0].ControlID != "AC-2" {
		t.Fatalf("dashboard = %+v, want one entry for AC-2", dashboard)
	}
	// "AC-3" was never recorded — it simply does not appear (a gap by
	// absence), never a fabricated zero-evidence row.
	for _, d := range dashboard {
		if d.ControlID == "AC-3" {
			t.Error("a control with no recorded evidence must not appear in the dashboard")
		}
	}
}
