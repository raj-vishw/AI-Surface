package investigation

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// ClusterStatus tracks whether an analyst has acted on a suggested
// grouping (phase9.md §40/§42). Automatic grouping never merges or
// creates an Investigation on its own — it only ever proposes a Suggested
// cluster, which an analyst explicitly Accepts (converting it into a real
// Investigation) or Rejects. A rejected cluster is preserved, never
// deleted (phase9.md §42).
type ClusterStatus string

// Recognized cluster statuses.
const (
	ClusterSuggested ClusterStatus = "suggested"
	ClusterAccepted  ClusterStatus = "accepted"
	ClusterRejected  ClusterStatus = "rejected"
)

var validClusterStatuses = map[ClusterStatus]bool{
	ClusterSuggested: true, ClusterAccepted: true, ClusterRejected: true,
}

// Valid reports whether s is a recognized cluster status.
func (s ClusterStatus) Valid() bool { return validClusterStatuses[s] }

// IncidentCluster is a system-suggested grouping of related
// findings/assets/endpoints that *might* warrant an investigation
// (phase9.md §41) — never itself a confirmed incident.
type IncidentCluster struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	Title      string
	Confidence Confidence
	Status     ClusterStatus

	// AcceptedInvestigationID is set once an analyst accepts this cluster,
	// pointing at the Investigation it was converted into (phase9.md §41's
	// "analysts can convert/accept a cluster into an investigation").
	AcceptedInvestigationID *uuid.UUID

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that c is internally consistent.
func (c IncidentCluster) Validate() error {
	var errs validation.Errors

	if c.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if strings.TrimSpace(c.Title) == "" {
		errs = errs.Add("title", "must not be empty")
	}
	if !c.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if !c.Status.Valid() {
		errs = errs.Add("status", "must be a recognized cluster status")
	}

	return errs.ErrOrNil()
}

// ClusterItem is one entity (finding/asset/endpoint) belonging to an
// IncidentCluster (phase9.md §41's "it contains related findings, assets,
// endpoints, events").
type ClusterItem struct {
	ID        uuid.UUID
	ClusterID uuid.UUID

	SourceType EntityType
	SourceID   uuid.UUID

	CreatedAt time.Time
}

// Validate checks that i is internally consistent.
func (i ClusterItem) Validate() error {
	var errs validation.Errors

	if i.ClusterID == uuid.Nil {
		errs = errs.Add("cluster_id", "must not be empty")
	}
	if !i.SourceType.Valid() {
		errs = errs.Add("source_type", "must be a recognized entity type")
	}
	if i.SourceID == uuid.Nil {
		errs = errs.Add("source_id", "must not be empty")
	}

	return errs.ErrOrNil()
}
