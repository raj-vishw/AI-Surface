package ai

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type fakeTool struct {
	name       string
	maxResults int
	execute    func(context.Context, ToolScope, ToolArgs) (ToolResult, error)
}

func (f fakeTool) Name() string        { return f.name }
func (f fakeTool) Description() string { return "fake tool for tests" }
func (f fakeTool) MaxResults() int     { return f.maxResults }
func (f fakeTool) Execute(ctx context.Context, scope ToolScope, args ToolArgs) (ToolResult, error) {
	return f.execute(ctx, scope, args)
}

func TestExecutor_DeniesUnregisteredTool(t *testing.T) {
	registry := NewToolRegistry()
	var record ToolCallRecord
	exec := NewExecutor(registry, func(r ToolCallRecord) { record = r }, time.Second)

	_, err := exec.Call(context.Background(), "arbitrary_shell_command", ToolScope{TargetID: "t1"}, nil)
	if err == nil {
		t.Fatal("expected an error calling an unregistered tool")
	}
	if record.Status != "denied" {
		t.Errorf("audit status = %q, want denied", record.Status)
	}
}

func TestExecutor_EnforcesMaxResults(t *testing.T) {
	registry := NewToolRegistry()
	tool := fakeTool{name: "many_facts", maxResults: 2, execute: func(context.Context, ToolScope, ToolArgs) (ToolResult, error) {
		return ToolResult{Facts: []Fact{{ID: "1"}, {ID: "2"}, {ID: "3"}, {ID: "4"}}}, nil
	}}
	if err := registry.Register(tool); err != nil {
		t.Fatalf("Register: %v", err)
	}
	exec := NewExecutor(registry, nil, time.Second)

	result, err := exec.Call(context.Background(), "many_facts", ToolScope{TargetID: "t1"}, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if len(result.Facts) != 2 {
		t.Errorf("len(result.Facts) = %d, want 2 (MaxResults enforced by Executor)", len(result.Facts))
	}
	if !result.Truncated {
		t.Error("expected Truncated = true")
	}
}

func TestExecutor_TimesOutSlowTool(t *testing.T) {
	registry := NewToolRegistry()
	tool := fakeTool{name: "slow", maxResults: 10, execute: func(ctx context.Context, _ ToolScope, _ ToolArgs) (ToolResult, error) {
		select {
		case <-time.After(200 * time.Millisecond):
			return ToolResult{}, nil
		case <-ctx.Done():
			return ToolResult{}, ctx.Err()
		}
	}}
	if err := registry.Register(tool); err != nil {
		t.Fatalf("Register: %v", err)
	}
	exec := NewExecutor(registry, nil, 10*time.Millisecond)

	_, err := exec.Call(context.Background(), "slow", ToolScope{TargetID: "t1"}, nil)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestExecutor_AlwaysAudits_SuccessAndError(t *testing.T) {
	registry := NewToolRegistry()
	okTool := fakeTool{name: "ok", maxResults: 5, execute: func(context.Context, ToolScope, ToolArgs) (ToolResult, error) {
		return ToolResult{Facts: []Fact{{ID: "1"}}}, nil
	}}
	failTool := fakeTool{name: "fail", maxResults: 5, execute: func(context.Context, ToolScope, ToolArgs) (ToolResult, error) {
		return ToolResult{}, fmt.Errorf("boom")
	}}
	if err := registry.Register(okTool); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(failTool); err != nil {
		t.Fatal(err)
	}

	var records []ToolCallRecord
	exec := NewExecutor(registry, func(r ToolCallRecord) { records = append(records, r) }, time.Second)

	if _, err := exec.Call(context.Background(), "ok", ToolScope{TargetID: "t1"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.Call(context.Background(), "fail", ToolScope{TargetID: "t1"}, nil); err == nil {
		t.Fatal("expected error from fail tool")
	}

	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	if records[0].Status != "success" || records[1].Status != "error" {
		t.Errorf("statuses = %q, %q", records[0].Status, records[1].Status)
	}
}

func TestRequireString_RejectsMissingAndEmpty(t *testing.T) {
	if _, err := RequireString(ToolArgs{}, "id"); err == nil {
		t.Error("expected error for missing argument")
	}
	if _, err := RequireString(ToolArgs{"id": ""}, "id"); err == nil {
		t.Error("expected error for empty argument")
	}
	if _, err := RequireString(ToolArgs{"id": 5}, "id"); err == nil {
		t.Error("expected error for wrong-typed argument")
	}
	v, err := RequireString(ToolArgs{"id": "abc"}, "id")
	if err != nil || v != "abc" {
		t.Errorf("RequireString = (%q, %v), want (\"abc\", nil)", v, err)
	}
}

func TestOptionalLimit_ClampsToMax(t *testing.T) {
	if got := OptionalLimit(ToolArgs{"limit": 500}, 20); got != 20 {
		t.Errorf("OptionalLimit = %d, want clamped to 20", got)
	}
	if got := OptionalLimit(ToolArgs{}, 20); got != 20 {
		t.Errorf("OptionalLimit default = %d, want 20", got)
	}
	if got := OptionalLimit(ToolArgs{"limit": 5}, 20); got != 5 {
		t.Errorf("OptionalLimit = %d, want 5", got)
	}
}
