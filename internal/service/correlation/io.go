package correlation

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	domaincorrelation "ai-recon-platform/internal/domain/correlation"
)

// Export is the full, self-contained representation of one correlation
// returned by ai-recon correlation export — metadata, graph, evidence,
// timeline-relevant timestamps, confidence, strategy versions, and
// explanation (phase12.md §105). It never carries a secret: every field
// here is already public-within-the-platform data (phase12.md §105's "do
// not export secrets").
type Export struct {
	Correlation domaincorrelation.Correlation        `json:"correlation" yaml:"correlation"`
	Nodes       []domaincorrelation.Node             `json:"nodes" yaml:"nodes"`
	Edges       []domaincorrelation.Edge             `json:"edges" yaml:"edges"`
	Chain       *domaincorrelation.AttackChain       `json:"chain,omitempty" yaml:"chain,omitempty"`
	Stages      []domaincorrelation.AttackChainStage `json:"stages,omitempty" yaml:"stages,omitempty"`
}

// ExportCorrelation assembles id's full Export.
func (s *Service) ExportCorrelation(ctx context.Context, id uuid.UUID) (Export, error) {
	c, err := s.correlations.GetCorrelationByID(ctx, id)
	if err != nil {
		return Export{}, err
	}
	nodes, err := s.nodes.ListNodes(ctx, id)
	if err != nil {
		return Export{}, err
	}
	edges, err := s.edges.ListEdges(ctx, id)
	if err != nil {
		return Export{}, err
	}
	out := Export{Correlation: c, Nodes: nodes, Edges: edges}

	if chain, stages, err := s.GetChain(ctx, id); err == nil {
		out.Chain = &chain
		out.Stages = stages
	}
	return out, nil
}

// EncodeJSON encodes e as indented JSON.
func EncodeJSON(e Export) ([]byte, error) { return json.MarshalIndent(e, "", "  ") }

// EncodeYAML encodes e as YAML.
func EncodeYAML(e Export) ([]byte, error) { return yaml.Marshal(e) }
