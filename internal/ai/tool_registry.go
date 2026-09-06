package ai

import (
	"fmt"
	"sort"
	"sync"
)

// ToolRegistry is the allowlist of every Tool the assistant may call
// (phase13.md §29: "only explicitly registered tools may execute") —
// mirrors internal/correlation.StrategyRegistry's shape exactly.
type ToolRegistry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewToolRegistry returns an empty registry.
func NewToolRegistry() *ToolRegistry { return &ToolRegistry{tools: make(map[string]Tool)} }

// Register adds t under t.Name(), rejecting a nil tool or an empty name.
func (r *ToolRegistry) Register(t Tool) error {
	if t == nil {
		return fmt.Errorf("tool must not be nil")
	}
	if t.Name() == "" {
		return fmt.Errorf("tool name must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
	return nil
}

// Get returns the tool registered under name, or an error if it is not on
// the allowlist — the only path Executor uses to look up a tool, so an
// unregistered name can never execute (phase13.md §29).
func (r *ToolRegistry) Get(name string) (Tool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("tool %q is not registered", name)
	}
	return t, nil
}

// Names returns every registered tool name, sorted.
func (r *ToolRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
