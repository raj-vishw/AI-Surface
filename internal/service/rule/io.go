package rule

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	domainrule "ai-recon-platform/internal/domain/rule"
	domaintarget "ai-recon-platform/internal/domain/target"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/ruleengine"
)

// ExportedRule is the full, self-contained representation `ai-recon
// detection export` writes and `ai-recon detection import` reads back
// (phase11.md §69/§70) — no secrets or internal credentials
// (phase11.md §69: this platform has none in the rule model to begin
// with, so nothing is deliberately excluded beyond the Definition/
// metadata already shown here).
type ExportedRule struct {
	Name             string                `json:"name" yaml:"name"`
	Description      string                `json:"description,omitempty" yaml:"description,omitempty"`
	Category         string                `json:"category,omitempty" yaml:"category,omitempty"`
	Tags             []string              `json:"tags,omitempty" yaml:"tags,omitempty"`
	References       []string              `json:"references,omitempty" yaml:"references,omitempty"`
	DocumentationURL string                `json:"documentation_url,omitempty" yaml:"documentation_url,omitempty"`
	Definition       ruleengine.Definition `json:"-" yaml:"-"`
}

// Export builds an ExportedRule for ruleID's latest version.
func (s *Service) Export(ctx context.Context, ruleID uuid.UUID) (ExportedRule, ruleengine.Definition, error) {
	r, err := s.rules.GetRuleByID(ctx, ruleID)
	if err != nil {
		return ExportedRule{}, ruleengine.Definition{}, err
	}
	version, err := s.versions.GetLatest(ctx, ruleID)
	if err != nil {
		return ExportedRule{}, ruleengine.Definition{}, err
	}
	def, err := ruleengine.ParseJSON([]byte(version.Definition))
	if err != nil {
		return ExportedRule{}, ruleengine.Definition{}, fmt.Errorf("parsing persisted definition: %w", err)
	}
	return ExportedRule{
		Name: r.Name, Description: r.Description, Category: r.Category,
		Tags: r.Tags, References: r.References, DocumentationURL: r.DocumentationURL,
	}, def, nil
}

// ImportInput describes a rule import request.
type ImportInput struct {
	TargetType  domaintarget.Type
	TargetValue string
	Rule        ExportedRule
	Definition  ruleengine.Definition
	CreatedBy   string
	// Enable, if true, immediately enables the imported rule — the
	// default is StatusDraft (phase11.md §70: "imported rules should
	// initially be draft unless explicitly enabled").
	Enable bool
}

// Import validates, then persists an imported rule (phase11.md §70/§71)
// — an invalid definition is rejected before anything is written, and
// nothing is ever evaluated during import.
func (s *Service) Import(ctx context.Context, input ImportInput) (domainrule.Rule, domainrule.Version, error) {
	if _, err := ruleengine.Compile(input.Definition); err != nil {
		return domainrule.Rule{}, domainrule.Version{}, apperrors.NewValidation("imported rule definition is invalid", err)
	}
	created, version, err := s.CreateRule(ctx, CreateInput{
		TargetType: input.TargetType, TargetValue: input.TargetValue,
		Name: input.Rule.Name, Description: input.Rule.Description, Category: input.Rule.Category,
		Tags: input.Rule.Tags, References: input.Rule.References, DocumentationURL: input.Rule.DocumentationURL,
		Definition: input.Definition, ChangeDescription: "imported", CreatedBy: input.CreatedBy,
	})
	if err != nil {
		return domainrule.Rule{}, domainrule.Version{}, err
	}
	if input.Enable {
		created, err = s.Enable(ctx, created.ID, input.CreatedBy)
		if err != nil {
			return domainrule.Rule{}, domainrule.Version{}, err
		}
	}
	return created, version, nil
}
