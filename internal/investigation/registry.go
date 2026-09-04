package investigation

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// RuleMeta describes a registered rule without exposing the Rule
// interface itself — used for listing/introspection.
type RuleMeta struct {
	ID          string
	Name        string
	Description string
	Version     int
	Enabled     bool
}

// Registry holds every known Rule and whether each is currently enabled
// — mirrors internal/detection.Registry exactly.
type Registry struct {
	mu      sync.RWMutex
	rules   map[string]Rule
	enabled map[string]bool
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{rules: map[string]Rule{}, enabled: map[string]bool{}}
}

// Register adds r to the registry, enabled by default. Returns an error
// if r's ID is empty or already registered.
func (reg *Registry) Register(r Rule) error {
	id := strings.TrimSpace(r.ID())
	if id == "" {
		return fmt.Errorf("rule has an empty id")
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if _, exists := reg.rules[id]; exists {
		return fmt.Errorf("rule %q is already registered", id)
	}
	reg.rules[id] = r
	reg.enabled[id] = true
	return nil
}

// Get returns the rule with the given id.
func (reg *Registry) Get(id string) (Rule, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	r, ok := reg.rules[id]
	return r, ok
}

// All returns every registered rule, ordered by ID for deterministic
// output.
func (reg *Registry) All() []Rule {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	ids := make([]string, 0, len(reg.rules))
	for id := range reg.rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Rule, len(ids))
	for i, id := range ids {
		out[i] = reg.rules[id]
	}
	return out
}

// SetEnabled changes whether id runs in future Active calls.
func (reg *Registry) SetEnabled(id string, enabled bool) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if _, ok := reg.rules[id]; !ok {
		return
	}
	reg.enabled[id] = enabled
}

// Enabled reports whether id currently runs.
func (reg *Registry) Enabled(id string) bool {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	if _, ok := reg.rules[id]; !ok {
		return false
	}
	return reg.enabled[id]
}

// Metadata returns RuleMeta for every registered rule, ordered by ID.
func (reg *Registry) Metadata() []RuleMeta {
	all := reg.All()
	out := make([]RuleMeta, len(all))
	for i, r := range all {
		out[i] = RuleMeta{ID: r.ID(), Name: r.Name(), Description: r.Description(), Version: r.Version(), Enabled: reg.Enabled(r.ID())}
	}
	return out
}

// Active returns every enabled rule.
func (reg *Registry) Active() []Rule {
	all := reg.All()
	out := make([]Rule, 0, len(all))
	for _, r := range all {
		if reg.Enabled(r.ID()) {
			out = append(out, r)
		}
	}
	return out
}
