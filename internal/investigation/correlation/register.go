package correlation

import "ai-surface-platform/internal/investigation"

// RegisterAll registers every built-in correlation rule into r.
func RegisterAll(r *investigation.Registry) error {
	all := []investigation.Rule{
		sameAssetRule{},
		sameEndpointRule{},
		temporalProximityRule{},
		technologyRule{},
		sameServiceRule{},
		changeBasedRule{},
		authenticationColocationRule{},
		newAssetWithFindingRule{},
	}
	for _, rule := range all {
		if err := r.Register(rule); err != nil {
			return err
		}
	}
	return nil
}
