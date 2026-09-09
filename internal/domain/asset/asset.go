// Package asset defines the platform's canonical Asset model: anything
// discovered within an authorized target's scope (a host, an IP, an open
// port, an HTTP or AI endpoint, a repository, a cloud resource, ...), plus
// the evidence records that justify believing it exists.
package asset

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Type identifies what kind of thing an Asset represents. Stable string
// identifiers are used so new types can be added without renumbering
// existing rows or hard-coding business logic around ordinal values.
type Type string

// Recognized asset types.
const (
	TypeDomain        Type = "DOMAIN"
	TypeSubdomain     Type = "SUBDOMAIN"
	TypeHost          Type = "HOST"
	TypeIP            Type = "IP"
	TypePort          Type = "PORT"
	TypeService       Type = "SERVICE"
	TypeHTTPEndpoint  Type = "HTTP_ENDPOINT"
	TypeAPIEndpoint   Type = "API_ENDPOINT"
	TypeAIEndpoint    Type = "AI_ENDPOINT"
	TypeRepository    Type = "REPOSITORY"
	TypeCloudResource Type = "CLOUD_RESOURCE"
	TypeModelEndpoint Type = "MODEL_ENDPOINT"
)

var validTypes = map[Type]bool{
	TypeDomain: true, TypeSubdomain: true, TypeHost: true, TypeIP: true,
	TypePort: true, TypeService: true, TypeHTTPEndpoint: true,
	TypeAPIEndpoint: true, TypeAIEndpoint: true, TypeRepository: true,
	TypeCloudResource: true, TypeModelEndpoint: true,
}

// Valid reports whether t is a recognized asset type.
func (t Type) Valid() bool { return validTypes[t] }

// hostnameTypes are asset types identified by a hostname.
var hostnameTypes = map[Type]bool{TypeDomain: true, TypeSubdomain: true, TypeHost: true}

// endpointTypes are asset types identified by a URL.
var endpointTypes = map[Type]bool{TypeHTTPEndpoint: true, TypeAPIEndpoint: true, TypeAIEndpoint: true}

// portTypes are asset types identified by host+port+protocol.
var portTypes = map[Type]bool{TypePort: true, TypeService: true}

// Status tracks an asset's observed lifecycle state. Future discovery
// modules may update it, but a status change is always an explicit action —
// nothing in this package (or the persistence layer) marks an asset
// INACTIVE merely because one scan didn't observe it again. See
// service/asset for the explicit UpdateStatus / Retire operations.
type Status string

// Recognized asset statuses.
const (
	StatusDiscovered Status = "DISCOVERED"
	StatusActive     Status = "ACTIVE"
	StatusInactive   Status = "INACTIVE"
	StatusUnknown    Status = "UNKNOWN"
	StatusRetired    Status = "RETIRED"
)

var validStatuses = map[Status]bool{
	StatusDiscovered: true, StatusActive: true, StatusInactive: true,
	StatusUnknown: true, StatusRetired: true,
}

// Valid reports whether s is a recognized asset status.
func (s Status) Valid() bool { return validStatuses[s] }

// Confidence is a normalized score in [0.0, 1.0] expressing how sure a
// discovery source is that an asset genuinely exists / was correctly
// classified.
type Confidence float64

// Confidence level boundaries. Level buckets confidence scores so callers
// (services, reports, future risk scoring) don't each reinvent the
// thresholds. The boundaries are inclusive of their lower bound.
const (
	thresholdLow       = 0.25
	thresholdMedium    = 0.5
	thresholdHigh      = 0.75
	thresholdConfirmed = 1.0
)

// Level names a bucketed Confidence value.
type Level string

// Recognized confidence levels, low to high.
const (
	LevelUnknown   Level = "UNKNOWN"
	LevelLow       Level = "LOW"
	LevelMedium    Level = "MEDIUM"
	LevelHigh      Level = "HIGH"
	LevelConfirmed Level = "CONFIRMED"
)

// Validate reports whether c falls within the valid [0.0, 1.0] range.
func (c Confidence) Validate() error {
	if c < 0.0 || c > 1.0 {
		var errs validation.Errors
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
		return errs.ErrOrNil()
	}
	return nil
}

// Level buckets c into a named confidence level. An out-of-range value
// (which Validate would reject) is reported as LevelUnknown rather than
// panicking or extrapolating.
func (c Confidence) Level() Level {
	switch {
	case c < 0 || c > 1:
		return LevelUnknown
	case c >= thresholdConfirmed:
		return LevelConfirmed
	case c >= thresholdHigh:
		return LevelHigh
	case c >= thresholdMedium:
		return LevelMedium
	case c >= thresholdLow:
		return LevelLow
	default:
		return LevelUnknown
	}
}

// Asset is the canonical record of something discovered within a target's
// scope. Fields that don't apply to every asset type (Hostname, IP, Port,
// ...) are nullable pointers rather than zero-valued strings/ints: a zero
// value would falsely claim "port 0" or "empty hostname" instead of
// honestly representing "unknown / not applicable".
type Asset struct {
	ID             uuid.UUID
	TargetID       uuid.UUID
	OrganizationID *uuid.UUID
	Type           Type
	Hostname       *string
	IP             *string
	Port           *int
	Protocol       *string
	URL            *string
	Technology     *string
	Provider       *string
	Model          *string
	Environment    *string
	Source         string
	IdentityKey    string
	FirstSeen      time.Time
	LastSeen       time.Time
	Status         Status
	Confidence     Confidence
	Metadata       map[string]any
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Validate checks that a is internally consistent: a recognized type and
// status, a valid confidence, a non-empty source, and the fields required
// to compute a deterministic identity for its type (see Identity). It
// performs no network requests.
func (a Asset) Validate() error {
	var errs validation.Errors

	if a.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !a.Type.Valid() {
		errs = errs.Add("type", "must be a recognized asset type")
	}
	if a.Status != "" && !a.Status.Valid() {
		errs = errs.Add("status", "must be a recognized asset status")
	}
	if strings.TrimSpace(a.Source) == "" {
		errs = errs.Add("source", "must not be empty")
	}
	if err := a.Confidence.Validate(); err != nil {
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
	}
	if a.Port != nil && (*a.Port < 1 || *a.Port > 65535) {
		errs = errs.Add("port", "must be between 1 and 65535")
	}

	if a.Type.Valid() {
		if _, err := Identity(a); err != nil {
			errs = errs.Add("identity", err.Error())
		}
	}

	return errs.ErrOrNil()
}

// StringField returns *s, or "" if s is nil. Small helper to keep repository
// and service code from repeating nil checks for every optional field.
func StringField(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
