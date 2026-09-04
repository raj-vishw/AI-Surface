package detection

// Severity answers "how serious could this issue be?" — a property of the
// condition itself, independent of Confidence, which answers "how sure are
// we the condition is actually present" (phase8.md §12/§57: the two are
// never mixed. A detector must never report every finding as critical —
// each detector documents its own severity rule inline, see detectors/*.go).
type Severity string

// Recognized severities, informational to critical.
const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInformational: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Valid reports whether s is a recognized severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// Rank returns s's ordinal position (0 = informational, 4 = critical). An
// unrecognized severity ranks below informational (-1) rather than
// panicking.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// Category classifies what kind of security condition a Finding
// represents (phase8.md §46) — the same closed vocabulary
// internal/domain/finding.Category uses (kept as an independent copy, not
// an import, for the same self-contained-engine reason every type in this
// file is).
type Category string

// Recognized finding categories.
const (
	CategoryConfiguration         Category = "configuration"
	CategoryAuthentication        Category = "authentication"
	CategoryAuthorization         Category = "authorization"
	CategoryCryptography          Category = "cryptography"
	CategoryInformationDisclosure Category = "information_disclosure"
	CategoryExposure              Category = "exposure"
	CategoryAPI                   Category = "api"
	CategoryWeb                   Category = "web"
	CategoryInfrastructure        Category = "infrastructure"
	CategoryTechnology            Category = "technology"
	CategoryCertificate           Category = "certificate"
	CategorySecurityHeaders       Category = "security_headers"
)

// Scope names the granularity a Finding applies at (phase8.md §45).
type Scope string

// Recognized finding scopes.
const (
	ScopeAsset    Scope = "asset"
	ScopeEndpoint Scope = "endpoint"
	ScopeTarget   Scope = "target"
)
