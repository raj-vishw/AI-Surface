package detection

import (
	"context"
	"testing"
)

type stubDetector struct {
	id       string
	mode     DetectorMode
	findings []Finding
	err      error
}

func (s stubDetector) ID() string          { return s.id }
func (s stubDetector) Name() string        { return "stub " + s.id }
func (s stubDetector) Description() string { return "stub detector" }
func (s stubDetector) Version() int        { return 1 }
func (s stubDetector) Category() Category  { return CategoryConfiguration }
func (s stubDetector) Mode() DetectorMode  { return s.mode }
func (s stubDetector) Detect(_ context.Context, _ Input) ([]Finding, error) {
	return s.findings, s.err
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	d := stubDetector{id: "a", mode: DetectorPassive}
	if err := r.Register(d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := r.Get("a")
	if !ok || got.ID() != "a" {
		t.Fatalf("expected to find detector 'a', got %v %v", got, ok)
	}
}

func TestRegistry_RegisterRejectsEmptyID(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubDetector{id: "", mode: DetectorPassive}); err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestRegistry_RegisterRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	d := stubDetector{id: "a", mode: DetectorPassive}
	if err := r.Register(d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := r.Register(d); err == nil {
		t.Fatal("expected error registering the same id twice")
	}
}

func TestRegistry_SetEnabled(t *testing.T) {
	r := NewRegistry()
	d := stubDetector{id: "a", mode: DetectorPassive}
	_ = r.Register(d)

	if !r.Enabled("a") {
		t.Fatal("expected newly registered detector to be enabled by default")
	}
	r.SetEnabled("a", false)
	if r.Enabled("a") {
		t.Fatal("expected detector to be disabled after SetEnabled(false)")
	}
}

func TestRegistry_All_OrderedByID(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "zzz", mode: DetectorPassive})
	_ = r.Register(stubDetector{id: "aaa", mode: DetectorPassive})

	all := r.All()
	if len(all) != 2 || all[0].ID() != "aaa" || all[1].ID() != "zzz" {
		t.Fatalf("expected deterministic order [aaa zzz], got %v %v", all[0].ID(), all[1].ID())
	}
}

func TestRegistry_Active_PassiveAlwaysRuns(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "passive", mode: DetectorPassive})
	_ = r.Register(stubDetector{id: "active", mode: DetectorSafeActive})

	passiveOnly := r.Active(ModePassive)
	if len(passiveOnly) != 1 || passiveOnly[0].ID() != "passive" {
		t.Fatalf("expected only the passive detector under ModePassive, got %v", ids(passiveOnly))
	}

	both := r.Active(ModeSafeActive)
	if len(both) != 2 {
		t.Fatalf("expected both detectors under ModeSafeActive, got %v", ids(both))
	}
}

func TestRegistry_Active_ExcludesDisabled(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "a", mode: DetectorPassive})
	r.SetEnabled("a", false)

	if active := r.Active(ModePassive); len(active) != 0 {
		t.Fatalf("expected disabled detector excluded, got %v", ids(active))
	}
}

func TestRegistry_Metadata(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "a", mode: DetectorSafeActive})
	meta := r.Metadata()
	if len(meta) != 1 || meta[0].ID != "a" || meta[0].Mode != DetectorSafeActive || !meta[0].Enabled {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
}

func ids(detectors []Detector) []string {
	out := make([]string, len(detectors))
	for i, d := range detectors {
		out[i] = d.ID()
	}
	return out
}
