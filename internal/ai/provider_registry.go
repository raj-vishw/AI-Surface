package ai

import (
	"fmt"
	"sort"
	"sync"
)

// ProviderRegistry holds every configured Provider by name — mirrors
// internal/correlation.StrategyRegistry's shape and concurrency discipline
// exactly (phase13.md §3's "support a provider registry").
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewProviderRegistry returns an empty registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{providers: make(map[string]Provider)}
}

// Register adds p under p.Name(). Registering the same name twice replaces
// the previous provider — useful for tests that swap in a canned mock.
func (r *ProviderRegistry) Register(p Provider) error {
	if p == nil {
		return fmt.Errorf("provider must not be nil")
	}
	name := p.Name()
	if name == "" {
		return fmt.Errorf("provider name must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[name] = p
	return nil
}

// Get returns the provider registered under name, or an error if none is.
func (r *ProviderRegistry) Get(name string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("no AI provider registered under name %q", name)
	}
	return p, nil
}

// Names returns every registered provider name, sorted.
func (r *ProviderRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
