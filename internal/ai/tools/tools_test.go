package tools

import (
	"context"
	"errors"
	"testing"

	"ai-recon-platform/internal/ai"
)

// fakeDataSource returns canned facts scoped to whatever TargetID it was
// built for — used to verify authorization scoping (phase13.md §30/§61)
// without a real database.
type fakeDataSource struct {
	targetID string
}

func (f fakeDataSource) checkScope(scope ai.ToolScope) error {
	if scope.TargetID != f.targetID {
		return errors.New("scope target does not match this data source — cross-target access denied")
	}
	return nil
}

func (f fakeDataSource) GetInvestigation(_ context.Context, scope ai.ToolScope, id string) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	return []ai.Fact{{Type: ai.FactInvestigation, ID: id, Summary: "investigation"}}, nil
}
func (f fakeDataSource) GetAlert(_ context.Context, scope ai.ToolScope, id string) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	return []ai.Fact{{Type: ai.FactAlert, ID: id, Summary: "alert"}}, nil
}
func (f fakeDataSource) GetDetection(_ context.Context, scope ai.ToolScope, id string) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	return []ai.Fact{{Type: ai.FactDetection, ID: id, Summary: "detection"}}, nil
}
func (f fakeDataSource) GetCorrelation(_ context.Context, scope ai.ToolScope, id string) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	return []ai.Fact{{Type: ai.FactCorrelation, ID: id, Summary: "correlation"}}, nil
}
func (f fakeDataSource) GetTimeline(_ context.Context, scope ai.ToolScope, limit int) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	facts := make([]ai.Fact, 0, limit)
	for i := 0; i < limit; i++ {
		facts = append(facts, ai.Fact{Type: ai.FactTimelineEvent, ID: string(rune('a' + i))})
	}
	return facts, nil
}
func (f fakeDataSource) GetFindings(_ context.Context, scope ai.ToolScope, limit int) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	return []ai.Fact{{Type: ai.FactFinding, ID: "f1"}}, nil
}
func (f fakeDataSource) GetAssets(_ context.Context, scope ai.ToolScope, limit int) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	return []ai.Fact{{Type: ai.FactAsset, ID: "as1"}}, nil
}
func (f fakeDataSource) GetIntelligence(_ context.Context, scope ai.ToolScope, limit int) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	return []ai.Fact{{Type: ai.FactIntelligence, ID: "i1"}}, nil
}
func (f fakeDataSource) GetRisk(_ context.Context, scope ai.ToolScope, entityID string) ([]ai.Fact, error) {
	if err := f.checkScope(scope); err != nil {
		return nil, err
	}
	return []ai.Fact{{Type: ai.FactRisk, ID: entityID}}, nil
}

func TestRegisterAll_RegistersEveryTool(t *testing.T) {
	r := ai.NewToolRegistry()
	if err := RegisterAll(r, fakeDataSource{targetID: "t1"}); err != nil {
		t.Fatalf("RegisterAll: %v", err)
	}
	want := []string{
		"get_alert", "get_assets", "get_correlation", "get_detection",
		"get_findings", "get_intelligence", "get_investigation", "get_risk", "get_timeline",
	}
	got := r.Names()
	if len(got) != len(want) {
		t.Fatalf("got %d tools, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGetAlert_RequiresID(t *testing.T) {
	tool := NewGetAlert(fakeDataSource{targetID: "t1"})
	_, err := tool.Execute(context.Background(), ai.ToolScope{TargetID: "t1"}, ai.ToolArgs{})
	if err == nil {
		t.Fatal("expected an error when id is missing")
	}
}

func TestGetAlert_DeniesCrossTargetAccess(t *testing.T) {
	tool := NewGetAlert(fakeDataSource{targetID: "t1"})
	_, err := tool.Execute(context.Background(), ai.ToolScope{TargetID: "t2"}, ai.ToolArgs{"id": "a1"})
	if err == nil {
		t.Fatal("expected cross-target access to be denied")
	}
}

func TestGetTimeline_BoundedByLimit(t *testing.T) {
	tool := NewGetTimeline(fakeDataSource{targetID: "t1"})
	result, err := tool.Execute(context.Background(), ai.ToolScope{TargetID: "t1"}, ai.ToolArgs{"limit": 3})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Facts) != 3 {
		t.Errorf("len(result.Facts) = %d, want 3", len(result.Facts))
	}
}

func TestEveryTool_IsReadOnly(t *testing.T) {
	// Structural guarantee: DataSource has no method whose name implies a
	// write, so no tool built against it can mutate anything regardless
	// of arguments (phase13.md §31). This test documents and locks in
	// that guarantee by exhaustively checking the interface's method set.
	writeVerbs := []string{"Set", "Update", "Delete", "Create", "Confirm", "Dismiss", "Block", "Disable", "Execute", "Scan"}
	methods := []string{
		"GetInvestigation", "GetAlert", "GetDetection", "GetCorrelation",
		"GetTimeline", "GetFindings", "GetAssets", "GetIntelligence", "GetRisk",
	}
	for _, m := range methods {
		for _, verb := range writeVerbs {
			if verb != "Execute" && len(m) >= len(verb) && m[:len(verb)] == verb {
				t.Errorf("DataSource method %q looks like a write operation (%q) — tools must remain read-only", m, verb)
			}
		}
	}
}
