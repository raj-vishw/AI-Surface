package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// benchStrategy is a minimal Strategy standing in for the temporal
// strategy's own sort-then-window approach, so this benchmark measures
// Engine/Graph overhead independent of internal/correlation/strategies'
// import (avoiding an import cycle: strategies imports this package).
type benchTemporalStrategy struct{}

func (benchTemporalStrategy) ID() string          { return "bench_temporal" }
func (benchTemporalStrategy) Name() string        { return "bench" }
func (benchTemporalStrategy) Description() string { return "bench" }
func (benchTemporalStrategy) Version() int        { return 1 }
func (benchTemporalStrategy) Evaluate(_ context.Context, input Input) ([]Edge, error) {
	window := input.Config.EffectiveTemporalWindow()
	obs := input.Observations
	var edges []Edge
	for i := 0; i < len(obs); i++ {
		for j := i + 1; j < len(obs) && obs[j].Timestamp.Sub(obs[i].Timestamp) <= window; j++ {
			edges = append(edges, Edge{
				Source: NodeRef{Type: obs[i].Type, ReferenceID: obs[i].ReferenceID}, Target: NodeRef{Type: obs[j].Type, ReferenceID: obs[j].ReferenceID},
				Relationship: RelationshipFollowedBy, Provenance: ProvenanceInferred, Confidence: ConfidenceLow, Evidence: "e",
			})
		}
	}
	return edges, nil
}

// benchObservations spaces observations 30s apart — realistic for a
// target's actual observation rate (not one every second forever), so
// the number of neighbors falling inside the 5-minute correlation window
// stays roughly constant (~10) regardless of n, keeping this benchmark's
// own memory use bounded (linear in n) rather than reflecting an
// unrealistic worst-case density no real deployment would present.
func benchObservations(n int) []Observation {
	base := time.Now()
	obs := make([]Observation, n)
	for i := range obs {
		obs[i] = Observation{Type: NodeFinding, ReferenceID: uuid.New(), Timestamp: base.Add(time.Duration(i) * 30 * time.Second)}
	}
	return obs
}

func benchmarkEngine(b *testing.B, n int) {
	reg := NewStrategyRegistry()
	_ = reg.Register(benchTemporalStrategy{})
	engine := NewEngine(reg)
	obs := benchObservations(n)
	cfg := Config{TemporalWindow: 5 * time.Minute, MaxCandidates: n + 1, MaxNodes: n + 1, MaxEdges: n * 20}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Correlate(context.Background(), Input{TargetID: uuid.New(), Observations: obs, Config: cfg})
	}
}

func BenchmarkEngine_1000Observations(b *testing.B)   { benchmarkEngine(b, 1000) }
func BenchmarkEngine_10000Observations(b *testing.B)  { benchmarkEngine(b, 10000) }
func BenchmarkEngine_100000Observations(b *testing.B) { benchmarkEngine(b, 100000) }

func BenchmarkComputeFingerprint(b *testing.B) {
	target := uuid.New()
	g := Graph{Nodes: []Node{nodeWith(NodeFinding, nil), nodeWith(NodeAsset, nil)}}
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeFingerprint(target, g, now, time.Hour)
	}
}
