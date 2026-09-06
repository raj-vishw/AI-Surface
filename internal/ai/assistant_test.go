package ai

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubProvider struct {
	name string
	fn   func(Request) (ProviderResponse, error)
}

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) Generate(_ context.Context, req Request) (ProviderResponse, error) {
	return s.fn(req)
}

func sampleContext() Context {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return Context{
		TargetID: "t1",
		Facts: []Fact{
			{Type: FactAlert, ID: "a1", Timestamp: base, Summary: "Repeated authentication failures followed by success", Provenance: ProvenanceObserved},
			{Type: FactAsset, ID: "as1", Timestamp: base, Summary: "example.com", Provenance: ProvenanceObserved},
		},
	}
}

func TestAssistant_Run_Deterministic_WithMockLikeProvider(t *testing.T) {
	a := NewAssistant()
	ctx := sampleContext()
	provider := stubProvider{name: "test", fn: func(req Request) (ProviderResponse, error) {
		return ProviderResponse{Content: req.UserPrompt, Model: "test-model"}, nil
	}}

	r1, err := a.Run(context.Background(), provider, TaskAlertExplanation, ctx, "", ExplainAlert)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	r2, err := a.Run(context.Background(), provider, TaskAlertExplanation, ctx, "", ExplainAlert)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r1.Content != r2.Content || r1.ContextHash != r2.ContextHash || r1.Confidence != r2.Confidence {
		t.Error("identical context + deterministic provider produced different results")
	}
}

func TestAssistant_Run_StripsFabricatedCitations(t *testing.T) {
	a := NewAssistant()
	ctx := sampleContext()
	provider := stubProvider{name: "test", fn: func(_ Request) (ProviderResponse, error) {
		return ProviderResponse{Content: "This references [alert:a1] and also [finding:FAKE-999].", Model: "test-model"}, nil
	}}

	r, err := a.Run(context.Background(), provider, TaskAlertExplanation, ctx, "", ExplainAlert)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.FabricatedCitationsRemoved) != 1 || r.FabricatedCitationsRemoved[0] != "[finding:FAKE-999]" {
		t.Errorf("FabricatedCitationsRemoved = %v, want [finding:FAKE-999]", r.FabricatedCitationsRemoved)
	}
	for _, c := range ExtractCitations(r.Content) {
		if c == "[finding:FAKE-999]" {
			t.Error("fabricated citation survived into final content")
		}
	}
}

func TestAssistant_Run_FallsBackOnAttribution(t *testing.T) {
	a := NewAssistant()
	ctx := sampleContext()
	provider := stubProvider{name: "test", fn: func(_ Request) (ProviderResponse, error) {
		return ProviderResponse{Content: "This attack is attributed to APT29.", Model: "test-model"}, nil
	}}

	r, err := a.Run(context.Background(), provider, TaskAlertExplanation, ctx, "", ExplainAlert)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !r.AttributionRejected || !r.UsedFallback {
		t.Errorf("AttributionRejected=%v UsedFallback=%v, want both true", r.AttributionRejected, r.UsedFallback)
	}
	if ContainsAttribution(r.Content) {
		t.Error("final content still contains attribution language")
	}
}

func TestAssistant_Run_ProviderErrorSurfacesClearly(t *testing.T) {
	a := NewAssistant()
	ctx := sampleContext()
	wantErr := errors.New("provider unavailable")
	provider := stubProvider{name: "test", fn: func(_ Request) (ProviderResponse, error) {
		return ProviderResponse{}, wantErr
	}}

	_, err := a.Run(context.Background(), provider, TaskAlertExplanation, ctx, "", ExplainAlert)
	if err == nil {
		t.Fatal("expected an error when the provider fails")
	}
}

func TestAssistant_Run_NilProviderErrors(t *testing.T) {
	a := NewAssistant()
	_, err := a.Run(context.Background(), nil, TaskAlertExplanation, sampleContext(), "", ExplainAlert)
	if err == nil {
		t.Fatal("expected an error for a nil provider")
	}
}
