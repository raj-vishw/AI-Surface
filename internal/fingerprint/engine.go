package fingerprint

import "sort"

// EngineConfig configures Engine.Evaluate's filtering/scoring behavior.
type EngineConfig struct {
	// MinConfidence filters out any result whose score falls below it —
	// applied after a signature's own MinScore override, if it declared
	// one (phase6.md §32).
	MinConfidence float64
	Thresholds    Thresholds
}

// Engine evaluates an Observation against a fixed, pre-loaded set of
// signatures — the matching/scoring/conflict-resolution/normalization
// pipeline (phase6.md §7/§8/§10/§11). It holds no observation state
// itself and is safe for concurrent use across goroutines analyzing
// different assets.
type Engine struct {
	signatures []CompiledSignature
	cfg        EngineConfig
}

// NewEngine builds an Engine over signatures, pre-loaded via
// LoadSignatures.
func NewEngine(signatures []CompiledSignature, cfg EngineConfig) *Engine {
	if cfg.Thresholds == (Thresholds{}) {
		cfg.Thresholds = DefaultThresholds
	}
	return &Engine{signatures: signatures, cfg: cfg}
}

// Evaluate matches every loaded signature against o, resolves declared
// incompatibilities (phase6.md §10), normalizes technology identities
// (phase6.md §11), filters by confidence, and returns results sorted
// deterministically (Category, then descending Confidence, then
// Technology) — the same result for the same Observation and signature
// set every time (phase6.md §7's "deterministic matcher").
func (e *Engine) Evaluate(o Observation) []Result {
	outcomes := make(map[string]matchOutcome, len(e.signatures))
	scores := make(map[string]float64, len(e.signatures))

	for _, sig := range e.signatures {
		outcome, ok := matchSignature(o, sig)
		if !ok {
			continue
		}
		s := score(outcome.signals, sig.compiledSignals)
		minConfidence := e.cfg.MinConfidence
		if sig.MinScore > 0 {
			minConfidence = sig.MinScore
		}
		if s < minConfidence {
			continue
		}
		outcomes[sig.Name] = outcome
		scores[sig.Name] = s
	}

	// Conflict handling (phase6.md §10): for every declared
	// incompatible pair that both matched, drop the lower-scoring one.
	// Ties are broken by signature name for determinism.
	dropped := make(map[string]bool)
	for name, outcome := range outcomes {
		if dropped[name] {
			continue
		}
		for _, other := range outcome.signature.IncompatibleWith {
			if dropped[other] {
				continue
			}
			if _, matched := outcomes[other]; !matched {
				continue
			}
			loser := weakerOf(name, scores[name], other, scores[other])
			dropped[loser] = true
		}
	}

	results := make([]Result, 0, len(outcomes))
	for name, outcome := range outcomes {
		if dropped[name] {
			continue
		}
		s := scores[name]
		results = append(results, Result{
			SignatureName: name,
			Category:      outcome.signature.Category,
			Technology:    NormalizeTechnology(pick(outcome.signature.Product, name)),
			Product:       outcome.signature.Product,
			Vendor:        outcome.signature.Vendor,
			Version:       outcome.version,
			Confidence:    s,
			Level:         e.cfg.Thresholds.Level(s),
			Signals:       outcome.signals,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Category != results[j].Category {
			return results[i].Category < results[j].Category
		}
		if results[i].Confidence != results[j].Confidence {
			return results[i].Confidence > results[j].Confidence
		}
		return results[i].Technology < results[j].Technology
	})
	return results
}

// weakerOf returns the name of the lower-scoring signature; ties resolve
// to the alphabetically-later name, so the outcome is fully deterministic
// regardless of Go's randomized map iteration order.
func weakerOf(nameA string, scoreA float64, nameB string, scoreB float64) string {
	if scoreA < scoreB {
		return nameA
	}
	if scoreB < scoreA {
		return nameB
	}
	if nameA > nameB {
		return nameA
	}
	return nameB
}

func pick(preferred, fallback string) string {
	if preferred != "" {
		return preferred
	}
	return fallback
}
