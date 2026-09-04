package investigation

import (
	"context"
	"testing"
)

type stubRule struct {
	id            string
	relationships []Relationship
	err           error
}

func (s stubRule) ID() string          { return s.id }
func (s stubRule) Name() string        { return "stub " + s.id }
func (s stubRule) Description() string { return "stub rule" }
func (s stubRule) Version() int        { return 1 }
func (s stubRule) Evaluate(_ context.Context, _ Input) ([]Relationship, error) {
	return s.relationships, s.err
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubRule{id: "a"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := r.Get("a")
	if !ok || got.ID() != "a" {
		t.Fatalf("expected to find rule 'a', got %v %v", got, ok)
	}
}

func TestRegistry_RegisterRejectsEmptyOrDuplicate(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubRule{id: ""}); err == nil {
		t.Fatal("expected error for empty id")
	}
	if err := r.Register(stubRule{id: "a"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := r.Register(stubRule{id: "a"}); err == nil {
		t.Fatal("expected error for duplicate id")
	}
}

func TestRegistry_SetEnabled(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubRule{id: "a"})
	if !r.Enabled("a") {
		t.Fatal("expected newly registered rule to be enabled by default")
	}
	r.SetEnabled("a", false)
	if r.Enabled("a") {
		t.Fatal("expected rule to be disabled after SetEnabled(false)")
	}
}

func TestRegistry_All_OrderedByID(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubRule{id: "zzz"})
	_ = r.Register(stubRule{id: "aaa"})
	all := r.All()
	if len(all) != 2 || all[0].ID() != "aaa" || all[1].ID() != "zzz" {
		t.Fatalf("expected deterministic order, got %v %v", all[0].ID(), all[1].ID())
	}
}

func TestRegistry_Active_ExcludesDisabled(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubRule{id: "a"})
	r.SetEnabled("a", false)
	if active := r.Active(); len(active) != 0 {
		t.Fatalf("expected disabled rule excluded, got %d", len(active))
	}
}

func TestRegistry_Metadata(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubRule{id: "a"})
	meta := r.Metadata()
	if len(meta) != 1 || meta[0].ID != "a" || !meta[0].Enabled {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
}
