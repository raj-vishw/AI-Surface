// Package target defines the Target domain model: the authorized scope a
// scan may operate against. A Target existing in the database is never, by
// itself, permission to act against it — see AuthorizationStatus.
package target

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// Type identifies what kind of thing a Target's Value names. Stable string
// identifiers are used (never numeric ordering) so new types can be added
// without renumbering existing rows.
type Type string

// Recognized target types.
const (
	TypeDomain       Type = "DOMAIN"
	TypeHost         Type = "HOST"
	TypeIP           Type = "IP"
	TypeCIDR         Type = "CIDR"
	TypeURL          Type = "URL"
	TypeRepository   Type = "REPOSITORY"
	TypeCloudAccount Type = "CLOUD_ACCOUNT"
)

// validTypes is used both for Type.Valid and to keep the switch in
// Validate exhaustive-by-construction.
var validTypes = map[Type]bool{
	TypeDomain:       true,
	TypeHost:         true,
	TypeIP:           true,
	TypeCIDR:         true,
	TypeURL:          true,
	TypeRepository:   true,
	TypeCloudAccount: true,
}

// Valid reports whether t is one of the recognized target types.
func (t Type) Valid() bool {
	return validTypes[t]
}

// AuthorizationStatus records whether a Target has been cleared for active
// operations. The system must never infer authorization from a Target's
// mere existence — callers gating active work must check this explicitly
// (see Target.IsAuthorized).
type AuthorizationStatus string

// Recognized authorization states.
const (
	AuthorizationUnverified AuthorizationStatus = "UNVERIFIED"
	AuthorizationAuthorized AuthorizationStatus = "AUTHORIZED"
	AuthorizationExpired    AuthorizationStatus = "EXPIRED"
	AuthorizationRevoked    AuthorizationStatus = "REVOKED"
)

var validAuthorizationStatuses = map[AuthorizationStatus]bool{
	AuthorizationUnverified: true,
	AuthorizationAuthorized: true,
	AuthorizationExpired:    true,
	AuthorizationRevoked:    true,
}

// Valid reports whether s is one of the recognized authorization states.
func (s AuthorizationStatus) Valid() bool {
	return validAuthorizationStatuses[s]
}

// Target represents the authorized scope being assessed.
type Target struct {
	ID                  uuid.UUID
	Name                string
	Type                Type
	Value               string
	Description         string
	AuthorizationStatus AuthorizationStatus
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// IsAuthorized reports whether active operations are currently permitted
// against t. This is the single boundary future scanning phases must
// consult before doing anything active; it is intentionally strict — only
// AUTHORIZED passes.
func (t Target) IsAuthorized() bool {
	return t.AuthorizationStatus == AuthorizationAuthorized
}

// Validate checks that t is internally consistent and well-formed. It
// performs no network requests or DNS lookups and is fully deterministic —
// the same Target always produces the same result. Future scanning
// components may reuse this before attempting to act on a target.
func (t Target) Validate() error {
	var errs validation.Errors

	if strings.TrimSpace(t.Name) == "" {
		errs = errs.Add("name", "must not be empty")
	}

	if !t.Type.Valid() {
		errs = errs.Add("type", "must be one of DOMAIN, HOST, IP, CIDR, URL, REPOSITORY, CLOUD_ACCOUNT")
	}

	value := strings.TrimSpace(t.Value)
	if value == "" {
		errs = errs.Add("value", "must not be empty")
	} else if t.Type.Valid() {
		if msg := validateValue(t.Type, value); msg != "" {
			errs = errs.Add("value", msg)
		}
	}

	if t.AuthorizationStatus != "" && !t.AuthorizationStatus.Valid() {
		errs = errs.Add("authorization_status", "must be one of UNVERIFIED, AUTHORIZED, EXPIRED, REVOKED")
	}

	return errs.ErrOrNil()
}

// validateValue applies type-specific format validation. It returns an
// empty string when value is well-formed for typ.
func validateValue(typ Type, value string) string {
	switch typ {
	case TypeDomain, TypeHost:
		if !isValidHostname(value) && net.ParseIP(value) == nil {
			return "must be a valid hostname or IP address"
		}
	case TypeIP:
		if net.ParseIP(value) == nil {
			return "must be a valid IP address"
		}
	case TypeCIDR:
		if _, _, err := net.ParseCIDR(value); err != nil {
			return "must be a valid CIDR block (e.g. 10.0.0.0/24)"
		}
	case TypeURL:
		u, err := url.Parse(value)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "must be a valid absolute URL with scheme and host"
		}
	case TypeRepository:
		if !isValidRepositoryReference(value) {
			return "must be a valid repository reference (URL, git@host:owner/repo, or owner/repo)"
		}
	case TypeCloudAccount:
		if !cloudAccountPattern.MatchString(value) {
			return "must be a non-empty cloud account identifier (alphanumeric, '-', '_', ':', '/')"
		}
	}
	return ""
}

// hostnameLabelPattern matches a single DNS label: 1-63 characters,
// alphanumeric, hyphens allowed but not leading/trailing.
var hostnameLabelPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// isValidHostname applies RFC 1035-style hostname validation: 1-253
// characters total, dot-separated labels each matching hostnameLabelPattern.
func isValidHostname(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(value, "."), ".")
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if !hostnameLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// repoURLSchemes are the URL schemes accepted for a REPOSITORY target given
// as a full URL.
var repoURLSchemes = map[string]bool{"https": true, "http": true, "git": true, "ssh": true}

// scpLikePattern matches the scp-like git syntax: user@host:owner/repo.
var scpLikePattern = regexp.MustCompile(`^[\w.-]+@[\w.-]+:[\w.\-/]+$`)

// ownerRepoPattern matches a bare GitHub/GitLab-style "owner/repo" shorthand.
var ownerRepoPattern = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)

// isValidRepositoryReference accepts a full repository URL, scp-like git
// syntax, or an "owner/repo" shorthand. No network request is made — this
// is a format check only.
func isValidRepositoryReference(value string) bool {
	if u, err := url.Parse(value); err == nil && repoURLSchemes[u.Scheme] && u.Host != "" {
		return true
	}
	if scpLikePattern.MatchString(value) {
		return true
	}
	return ownerRepoPattern.MatchString(value)
}

// cloudAccountPattern is deliberately permissive: cloud account identifiers
// vary widely (AWS account IDs, GCP project IDs, Azure subscription GUIDs,
// ARNs). It only rejects blank/whitespace-only or clearly malformed values.
var cloudAccountPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:_/.-]*$`)
