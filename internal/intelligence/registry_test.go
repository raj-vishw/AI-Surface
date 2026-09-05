package intelligence

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubProvider struct {
	id           string
	capabilities []Capability
	records      []Record
	err          error
}

func (p stubProvider) ID() string                 { return p.id }
func (p stubProvider) Name() string               { return "Stub " + p.id }
func (p stubProvider) Version() string            { return "1" }
func (p stubProvider) Capabilities() []Capability { return p.capabilities }
func (p stubProvider) Lookup(_ context.Context, i Indicator) ([]Record, error) {
	if p.err != nil {
		return nil, p.err
	}
	out := make([]Record, len(p.records))
	copy(out, p.records)
	for idx := range out {
		out[idx].Indicator = i
	}
	return out, nil
}

func TestRegistry_RegisterGetAllEnable(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubProvider{id: "a", capabilities: []Capability{CapabilityLocal}}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.Register(stubProvider{id: "b"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.Register(stubProvider{id: "a"}); err == nil {
		t.Fatal("expected error re-registering duplicate id")
	}
	if err := r.Register(stubProvider{id: ""}); err == nil {
		t.Fatal("expected error registering empty id")
	}

	if len(r.All()) != 2 {
		t.Fatalf("All() = %d providers, want 2", len(r.All()))
	}
	if !r.Enabled("a") {
		t.Fatal("expected a enabled by default")
	}
	r.SetEnabled("a", false)
	if r.Enabled("a") {
		t.Fatal("expected a disabled after SetEnabled(false)")
	}
	active := r.Active()
	if len(active) != 1 || active[0].ID() != "b" {
		t.Fatalf("Active() = %v, want only b", active)
	}

	meta := r.Metadata()
	if len(meta) != 2 {
		t.Fatalf("Metadata() = %d entries, want 2", len(meta))
	}
}

func TestRegistry_Health(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubProvider{id: "p"})

	h, ok := r.Health("p")
	if !ok || h.Status != HealthUnknown {
		t.Fatalf("expected unknown health before any call, got %+v", h)
	}

	r.RecordSuccess("p", 10*time.Millisecond)
	h, _ = r.Health("p")
	if h.Status != HealthHealthy || h.SuccessCount != 1 {
		t.Fatalf("expected healthy after success, got %+v", h)
	}

	r.RecordFailure("p", errors.New("boom"))
	r.RecordFailure("p", errors.New("boom"))
	r.RecordFailure("p", errors.New("boom"))
	h, _ = r.Health("p")
	if h.Status != HealthUnavailable {
		t.Fatalf("expected unavailable after 3 consecutive failures, got %s", h.Status)
	}
	if h.ErrorCount != 3 {
		t.Fatalf("expected error count 3, got %d", h.ErrorCount)
	}

	r.RecordSuccess("p", time.Millisecond)
	h, _ = r.Health("p")
	if h.Status != HealthHealthy {
		t.Fatalf("expected healthy again after a success, got %s", h.Status)
	}
}
