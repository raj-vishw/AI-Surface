package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// FactType names what kind of platform evidence one Fact represents —
// this engine's own citation-eligible vocabulary, independent of (but
// deliberately named after) internal/domain/investigation.EntityType and
// internal/domain/correlation.NodeType.
type FactType string

// Recognized fact types.
const (
	FactInvestigation FactType = "investigation"
	FactAlert         FactType = "alert"
	FactDetection     FactType = "detection"
	FactFinding       FactType = "finding"
	FactCorrelation   FactType = "correlation"
	FactAttackChain   FactType = "attack_chain"
	FactAsset         FactType = "asset"
	FactEndpoint      FactType = "endpoint"
	FactIntelligence  FactType = "intelligence"
	FactTimelineEvent FactType = "event"
	FactNote          FactType = "note"
	FactRisk          FactType = "risk"
	FactEdge          FactType = "edge"
	FactAttackStage   FactType = "stage"
)

// Provenance distinguishes a Fact directly retrieved from the platform's
// own records ("observed") from one this engine itself derived by
// combining others ("inferred") — never collapsed, mirroring
// internal/correlation.Provenance's identical discipline.
type Provenance string

// Recognized provenances.
const (
	ProvenanceObserved Provenance = "observed"
	ProvenanceInferred Provenance = "inferred"
)

// Fact is one atomic, already-redacted, already-summarized piece of
// evidence made available to a prompt or a deterministic structured-result
// builder. It is deliberately flat and small — never a full copy of a
// platform row — so that redaction (see redaction.go) and context-size
// limits (see limits.go) have one uniform shape to operate over regardless
// of which underlying repository the fact came from.
type Fact struct {
	Type FactType
	// ID is the underlying entity's own id (a uuid string, or, for a
	// synthetic fact like a risk score, a stable derived id) — this is
	// exactly the value a citation token embeds; it must never be
	// invented, only copied from the real record.
	ID string

	Timestamp time.Time

	// Summary is a short, human-readable, already-redacted statement of
	// what this fact is (e.g. "Alert: repeated authentication failures
	// followed by success (high severity, open)"). This is the only text
	// from this fact that a prompt or a rendered structured result ever
	// includes verbatim — Attributes are for citation-adjacent detail
	// only.
	Summary string

	Provenance Provenance

	// Attributes carries a small number of already-redacted key/value
	// details (severity, status, category, ...) — never raw secrets, never
	// unbounded blobs.
	Attributes map[string]string
}

// Citation returns the stable, bracketed reference token for this fact
// (phase13.md §14), e.g. "[alert:3fae...]". This is the only form a
// citation may legally take in generated output — see citations.go.
func (f Fact) Citation() string { return fmt.Sprintf("[%s:%s]", f.Type, f.ID) }

// Context is the complete, bounded, redacted, already-authorized bundle of
// evidence handed to a prompt for one AI task (phase13.md §10/§11).
// Building one from real repositories — including authorization scoping —
// is internal/service/ai's job (see ContextBuilder for the deterministic,
// DB-free primitives this package itself provides).
type Context struct {
	TargetID        string
	InvestigationID string // empty when the task is not investigation-scoped

	Facts []Fact

	// Truncated/TruncationNote record whether Limits forced facts to be
	// dropped, and, if so, an explicit note that must be surfaced to the
	// model and to the analyst (phase13.md §13: "Some evidence was omitted
	// because of context limits.").
	Truncated      bool
	TruncationNote string

	GeneratedAt time.Time
}

// CitationSet returns the set of every citation token legally usable for
// c — the allowlist citations.go's ValidateCitations checks generated
// output against.
func (c Context) CitationSet() map[string]bool {
	set := make(map[string]bool, len(c.Facts))
	for _, f := range c.Facts {
		set[f.Citation()] = true
	}
	return set
}

// FactsByType returns every fact of type t, in c's existing order.
func (c Context) FactsByType(t FactType) []Fact {
	var out []Fact
	for _, f := range c.Facts {
		if f.Type == t {
			out = append(out, f)
		}
	}
	return out
}

// HasType reports whether c contains at least one fact of type t.
func (c Context) HasType(t FactType) bool { return len(c.FactsByType(t)) > 0 }

// Hash computes a deterministic hash over c's normalized fact list
// (phase13.md §100) — sorted by (type, id) so that fact assembly order
// never changes the hash, only the actual evidence content does. This
// lets an audit trail record "which context was used" without storing the
// context itself.
func (c Context) Hash() string {
	facts := make([]Fact, len(c.Facts))
	copy(facts, c.Facts)
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].Type != facts[j].Type {
			return facts[i].Type < facts[j].Type
		}
		return facts[i].ID < facts[j].ID
	})

	h := sha256.New()
	fmt.Fprintf(h, "target=%s\ninvestigation=%s\n", c.TargetID, c.InvestigationID) //nolint:errcheck // hash.Hash.Write never errors
	for _, f := range facts {
		fmt.Fprintf(h, "%s|%s|%s|%s\n", f.Type, f.ID, f.Timestamp.UTC().Format(time.RFC3339), f.Summary) //nolint:errcheck // hash.Hash.Write never errors
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ResponseHash computes an integrity-verification hash over generated
// content (phase13.md §101).
func ResponseHash(content string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(content)))
	return hex.EncodeToString(sum[:])
}
