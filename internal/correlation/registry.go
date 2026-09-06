package correlation

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// StrategyMeta describes a registered strategy without exposing the
// Strategy interface itself — used for listing/introspection and for
// phase12.md §70's strategy-health tracking.
type StrategyMeta struct {
	ID          string
	Name        string
	Description string
	Version     int
	Enabled     bool
}

// StrategyRegistry holds every known Strategy and whether each is
// currently enabled (phase12.md §23) — mirrors
// internal/investigation.Registry and internal/detection.Registry
// exactly.
type StrategyRegistry struct {
	mu         sync.RWMutex
	strategies map[string]Strategy
	enabled    map[string]bool
}

// NewStrategyRegistry builds an empty StrategyRegistry.
func NewStrategyRegistry() *StrategyRegistry {
	return &StrategyRegistry{strategies: map[string]Strategy{}, enabled: map[string]bool{}}
}

// Register adds s to the registry, enabled by default. Returns an error
// if s's ID is empty or already registered.
func (reg *StrategyRegistry) Register(s Strategy) error {
	id := strings.TrimSpace(s.ID())
	if id == "" {
		return fmt.Errorf("strategy has an empty id")
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if _, exists := reg.strategies[id]; exists {
		return fmt.Errorf("strategy %q is already registered", id)
	}
	reg.strategies[id] = s
	reg.enabled[id] = true
	return nil
}

// Get returns the strategy with the given id.
func (reg *StrategyRegistry) Get(id string) (Strategy, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	s, ok := reg.strategies[id]
	return s, ok
}

// All returns every registered strategy, ordered by ID for deterministic
// output (phase12.md §25).
func (reg *StrategyRegistry) All() []Strategy {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	ids := make([]string, 0, len(reg.strategies))
	for id := range reg.strategies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Strategy, len(ids))
	for i, id := range ids {
		out[i] = reg.strategies[id]
	}
	return out
}

// SetEnabled changes whether id runs in future Active calls (phase12.md
// §23's "support enable/disable").
func (reg *StrategyRegistry) SetEnabled(id string, enabled bool) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if _, ok := reg.strategies[id]; !ok {
		return
	}
	reg.enabled[id] = enabled
}

// Enabled reports whether id currently runs.
func (reg *StrategyRegistry) Enabled(id string) bool {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	if _, ok := reg.strategies[id]; !ok {
		return false
	}
	return reg.enabled[id]
}

// Metadata returns StrategyMeta for every registered strategy, ordered by
// ID (phase12.md §23's "support list").
func (reg *StrategyRegistry) Metadata() []StrategyMeta {
	all := reg.All()
	out := make([]StrategyMeta, len(all))
	for i, s := range all {
		out[i] = StrategyMeta{ID: s.ID(), Name: s.Name(), Description: s.Description(), Version: s.Version(), Enabled: reg.Enabled(s.ID())}
	}
	return out
}

// Active returns every enabled strategy.
func (reg *StrategyRegistry) Active() []Strategy {
	all := reg.All()
	out := make([]Strategy, 0, len(all))
	for _, s := range all {
		if reg.Enabled(s.ID()) {
			out = append(out, s)
		}
	}
	return out
}
