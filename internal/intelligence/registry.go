package intelligence

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProviderMeta describes a registered provider without exposing the
// Provider interface itself (phase10.md §5).
type ProviderMeta struct {
	ID           string
	Name         string
	Version      string
	Capabilities []Capability
	Enabled      bool
}

// HealthStatus buckets a provider's recent reliability (phase10.md §74).
type HealthStatus string

// Recognized health statuses.
const (
	HealthUnknown     HealthStatus = "unknown" // never yet queried
	HealthHealthy     HealthStatus = "healthy"
	HealthDegraded    HealthStatus = "degraded"
	HealthUnavailable HealthStatus = "unavailable"
)

// ProviderHealth tracks one provider's recent outcomes (phase10.md §74/
// §75).
type ProviderHealth struct {
	Status       HealthStatus
	LastSuccess  time.Time
	LastError    string
	LastErrorAt  time.Time
	SuccessCount int
	ErrorCount   int
	LastLatency  time.Duration
}

// degradedThreshold/unavailableThreshold are consecutive-failure
// boundaries used by recomputeStatus — documented, fixed values rather
// than a configurable knob, since health is an operational signal, not a
// policy lever.
const (
	degradedAfterConsecutiveFailures    = 1
	unavailableAfterConsecutiveFailures = 3
)

// Registry holds every known Provider, whether each is currently enabled
// (phase10.md §5/§30), and its recent health (phase10.md §74). It mirrors
// internal/detection.Registry's shape and concurrency model exactly.
type Registry struct {
	mu          sync.RWMutex
	providers   map[string]Provider
	enabled     map[string]bool
	health      map[string]*ProviderHealth
	consecutive map[string]int // consecutive failures since last success, for health bucketing
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: map[string]Provider{}, enabled: map[string]bool{},
		health: map[string]*ProviderHealth{}, consecutive: map[string]int{},
	}
}

// Register adds p to the registry, enabled by default. It returns an
// error if p's ID is empty or already registered — a silent overwrite
// would let a provider's results be quietly replaced without anyone
// noticing, the same reasoning internal/detection.Registry.Register
// documents.
func (r *Registry) Register(p Provider) error {
	id := strings.TrimSpace(p.ID())
	if id == "" {
		return fmt.Errorf("provider has an empty id")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[id]; exists {
		return fmt.Errorf("provider %q is already registered", id)
	}
	r.providers[id] = p
	r.enabled[id] = true
	r.health[id] = &ProviderHealth{Status: HealthUnknown}
	return nil
}

// Get returns the provider with the given id.
func (r *Registry) Get(id string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	return p, ok
}

// All returns every registered provider, ordered by ID for deterministic
// output.
func (r *Registry) All() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.providers))
	for id := range r.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Provider, len(ids))
	for i, id := range ids {
		out[i] = r.providers[id]
	}
	return out
}

// SetEnabled changes whether id runs in future Active calls. A no-op if
// id isn't registered.
func (r *Registry) SetEnabled(id string, enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[id]; !ok {
		return
	}
	r.enabled[id] = enabled
}

// Enabled reports whether id currently runs.
func (r *Registry) Enabled(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.providers[id]; !ok {
		return false
	}
	return r.enabled[id]
}

// Active returns every enabled provider, ordered by ID.
func (r *Registry) Active() []Provider {
	all := r.All()
	out := make([]Provider, 0, len(all))
	for _, p := range all {
		if r.Enabled(p.ID()) {
			out = append(out, p)
		}
	}
	return out
}

// Metadata returns ProviderMeta for every registered provider, ordered by
// ID.
func (r *Registry) Metadata() []ProviderMeta {
	all := r.All()
	out := make([]ProviderMeta, len(all))
	for i, p := range all {
		out[i] = ProviderMeta{
			ID: p.ID(), Name: p.Name(), Version: p.Version(),
			Capabilities: p.Capabilities(), Enabled: r.Enabled(p.ID()),
		}
	}
	return out
}

// RecordSuccess updates id's health after a successful lookup.
func (r *Registry) RecordSuccess(id string, latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.health[id]
	if !ok {
		return
	}
	h.SuccessCount++
	h.LastSuccess = time.Now().UTC()
	h.LastLatency = latency
	r.consecutive[id] = 0
	h.Status = HealthHealthy
}

// RecordFailure updates id's health after a failed lookup.
func (r *Registry) RecordFailure(id string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.health[id]
	if !ok {
		return
	}
	h.ErrorCount++
	h.LastError = err.Error()
	h.LastErrorAt = time.Now().UTC()
	r.consecutive[id]++
	switch {
	case r.consecutive[id] >= unavailableAfterConsecutiveFailures:
		h.Status = HealthUnavailable
	case r.consecutive[id] >= degradedAfterConsecutiveFailures:
		h.Status = HealthDegraded
	}
}

// Health returns id's current health snapshot.
func (r *Registry) Health(id string) (ProviderHealth, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.health[id]
	if !ok {
		return ProviderHealth{}, false
	}
	return *h, true
}
