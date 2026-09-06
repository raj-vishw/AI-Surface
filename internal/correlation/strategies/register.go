package strategies

import "ai-recon-platform/internal/correlation"

// RegisterAll registers every built-in correlation strategy into r
// (phase12.md §22/§23).
func RegisterAll(r *correlation.StrategyRegistry) error {
	all := []correlation.Strategy{
		NewAsset(),
		NewTemporal(),
		NewIdentity(),
		NewNetwork(),
		NewDetection(),
		NewIntelligence(),
	}
	for _, s := range all {
		if err := r.Register(s); err != nil {
			return err
		}
	}
	return nil
}
