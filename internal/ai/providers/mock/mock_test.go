package mock

import (
	"context"
	"testing"

	"ai-recon-platform/internal/ai"
)

func TestProvider_Generate_DeterministicForIdenticalInput(t *testing.T) {
	p := New()
	req := ai.Request{TaskType: ai.TaskAlertExplanation, SystemPrompt: "sys", UserPrompt: "user data [alert:a1]"}

	r1, err := p.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r2, err := p.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if r1.Content != r2.Content {
		t.Error("mock provider produced different content for identical input")
	}
}

func TestProvider_Generate_RespectsCanceledContext(t *testing.T) {
	p := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Generate(ctx, ai.Request{})
	if err == nil {
		t.Fatal("expected an error for an already-canceled context")
	}
}

func TestProvider_Generate_ResponseFuncOverride(t *testing.T) {
	p := &Provider{ResponseFunc: func(ai.Request) (ai.ProviderResponse, error) {
		return ai.ProviderResponse{Content: "custom"}, nil
	}}
	resp, err := p.Generate(context.Background(), ai.Request{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.Content != "custom" {
		t.Errorf("Content = %q, want %q", resp.Content, "custom")
	}
	if resp.Model == "" {
		t.Error("expected a default model when ResponseFunc leaves it empty")
	}
}

func TestProvider_Name(t *testing.T) {
	if New().Name() != "mock" {
		t.Errorf("Name() = %q, want mock", New().Name())
	}
}
