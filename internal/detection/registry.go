package detection

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// DetectorMeta describes a registered detector without exposing the
// Detector interface itself — used for listing/introspection (phase8.md
// §6: "detector metadata, detector version").
type DetectorMeta struct {
	ID          string
	Name        string
	Description string
	Version     int
	Category    Category
	Mode        DetectorMode
	Enabled     bool
}

// Registry holds every known Detector and whether each is currently
// enabled (phase8.md §6). It never requires recompilation to disable a
// detector — SetEnabled changes runtime behavior immediately, and
// internal/service/detection wires it to Config.Detectors so it is also
// configurable via YAML/environment, exactly like every other subsystem
// in this project.
type Registry struct {
	mu        sync.RWMutex
	detectors map[string]Detector
	enabled   map[string]bool
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{detectors: map[string]Detector{}, enabled: map[string]bool{}}
}

// Register adds d to the registry, enabled by default. It returns an
// error if d's ID is empty or already registered — a silent overwrite
// would make it possible for a detector's findings to be quietly replaced
// by a same-named one without anyone noticing.
func (r *Registry) Register(d Detector) error {
	id := strings.TrimSpace(d.ID())
	if id == "" {
		return fmt.Errorf("detector has an empty id")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.detectors[id]; exists {
		return fmt.Errorf("detector %q is already registered", id)
	}
	r.detectors[id] = d
	r.enabled[id] = true
	return nil
}

// Get returns the detector with the given id.
func (r *Registry) Get(id string) (Detector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.detectors[id]
	return d, ok
}

// All returns every registered detector, ordered by ID for deterministic
// output.
func (r *Registry) All() []Detector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.detectors))
	for id := range r.detectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Detector, len(ids))
	for i, id := range ids {
		out[i] = r.detectors[id]
	}
	return out
}

// SetEnabled changes whether id runs in future Active calls. A no-op if
// id isn't registered.
func (r *Registry) SetEnabled(id string, enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.detectors[id]; !ok {
		return
	}
	r.enabled[id] = enabled
}

// Enabled reports whether id currently runs — true (enabled) for any
// registered id that was never explicitly disabled, false for an
// unregistered id.
func (r *Registry) Enabled(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.detectors[id]; !ok {
		return false
	}
	return r.enabled[id]
}

// Metadata returns DetectorMeta for every registered detector, ordered by
// ID.
func (r *Registry) Metadata() []DetectorMeta {
	all := r.All()
	out := make([]DetectorMeta, len(all))
	for i, d := range all {
		out[i] = DetectorMeta{
			ID: d.ID(), Name: d.Name(), Description: d.Description(),
			Version: d.Version(), Category: d.Category(), Mode: d.Mode(),
			Enabled: r.Enabled(d.ID()),
		}
	}
	return out
}

// Active returns every enabled detector eligible to run under mode:
// DetectorPassive detectors always run; DetectorSafeActive detectors run
// only when mode is ModeSafeActive (phase8.md §54: "default primarily to
// passive analysis").
func (r *Registry) Active(mode Mode) []Detector {
	all := r.All()
	out := make([]Detector, 0, len(all))
	for _, d := range all {
		if !r.Enabled(d.ID()) {
			continue
		}
		if d.Mode() == DetectorSafeActive && mode != ModeSafeActive {
			continue
		}
		out = append(out, d)
	}
	return out
}
