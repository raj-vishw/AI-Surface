package ai

import "context"

// Health reports the AI subsystem's own status (phase13.md §82) — never
// exposes credentials, only whether a provider is configured and appears
// reachable.
type Health struct {
	Enabled   bool
	Provider  string
	Available bool
	Reason    string
}

// CheckHealth implements phase13.md §82's GET /ai/health, adapted to this
// platform's CLI-only precedent (`ai-surface ai status`). It never performs
// a real provider round-trip on every health check — a lightweight
// "is a provider registered" check, not a billed API call.
func (s *Service) CheckHealth(_ context.Context, providerName string) Health {
	if providerName == "" {
		providerName = s.cfg.DefaultProvider
	}
	_, err := s.providers.Get(providerName)
	if err != nil {
		return Health{Enabled: true, Provider: providerName, Available: false, Reason: err.Error()}
	}
	return Health{Enabled: true, Provider: providerName, Available: true}
}
