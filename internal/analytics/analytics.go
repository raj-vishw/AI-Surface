// Package analytics implements Phase 14's dashboard/analytics layer on
// top of internal/repository/analytics's aggregate queries. It adds
// exactly what that package deliberately leaves out: time-range
// validation and interval auto-selection (phase14.md §20/§72/§73),
// bounded in-process caching with target-scoped keys (phase14.md §58/
// §59/§60), and the assembly of several repository calls into one
// dashboard-shaped response (Overview, SOC, AttackSurface, ...).
//
// TargetID scoping is this platform's authorization boundary throughout
// — the same adaptation every prior phase's own report documents: no
// auth/RBAC layer exists anywhere in this codebase, so "project
// isolation" (phase14.md §85/§86/§100) means every query is filtered by
// TargetID, and every cache key embeds it (phase14.md §59: "never allow
// cached data to cross project boundaries").
package analytics

import (
	"fmt"
	"time"

	apperrors "ai-surface-platform/internal/errors"
	analyticsrepo "ai-surface-platform/internal/repository/analytics"
)

// RangePreset names one of the four required presets (phase14.md §20).
type RangePreset string

// Recognized presets.
const (
	Range24h RangePreset = "24h"
	Range7d  RangePreset = "7d"
	Range30d RangePreset = "30d"
	Range90d RangePreset = "90d"
)

var presetDurations = map[RangePreset]time.Duration{
	Range24h: 24 * time.Hour,
	Range7d:  7 * 24 * time.Hour,
	Range30d: 30 * 24 * time.Hour,
	Range90d: 90 * 24 * time.Hour,
}

// DefaultIntervalFor returns the interval phase14.md §73's worked example
// specifies for a given preset: 24h -> hourly, 7d/30d -> daily,
// 90d -> weekly. An explicit interval (see ResolveRange) always
// overrides this.
func DefaultIntervalFor(preset RangePreset) string {
	switch preset {
	case Range24h:
		return "hour"
	case Range90d:
		return "week"
	default:
		return "day"
	}
}

// MaxQueryWindow bounds how wide an explicit [start, end) range may be —
// never unlimited, regardless of preset (phase14.md §72's "excessively
// large ranges" rejection). 90 days matches the widest supported preset;
// a caller needing a longer historical view should page through
// multiple bounded windows rather than requesting one unbounded query.
const MaxQueryWindow = 90 * 24 * time.Hour

// TimeRange is the resolved, explicit [Start, End) window plus the
// interval to bucket it by — this package's own copy, independent of
// internal/repository/analytics.TimeRange (mirrors that package's own
// "engine never imports the domain layer" independence, kept here so a
// caller of this package never needs to import the repository package
// directly). Timestamps are always UTC internally (phase14.md §21) —
// conversion to a viewer's local timezone is a presentation-only
// concern, never done before a query.
type TimeRange struct {
	Start    time.Time
	End      time.Time
	Interval string
}

func (r TimeRange) toRepo() analyticsrepo.TimeRange {
	return analyticsrepo.TimeRange{Start: r.Start, End: r.End}
}

// ResolveRange validates and resolves a time-range request (phase14.md
// §20/§72/§73). Exactly one of preset or (start, end) should be
// supplied — a non-empty preset always wins. interval, if non-empty,
// overrides the preset's own default (phase14.md §73: "allow explicit
// intervals where safe") and must be one of "hour"/"day"/"week".
func ResolveRange(preset RangePreset, start, end time.Time, interval string) (TimeRange, error) {
	now := time.Now().UTC()

	if preset != "" {
		dur, ok := presetDurations[preset]
		if !ok {
			return TimeRange{}, apperrors.NewValidation(fmt.Sprintf("unrecognized time range preset %q — must be one of 24h, 7d, 30d, 90d", preset), nil)
		}
		if interval == "" {
			interval = DefaultIntervalFor(preset)
		}
		if err := validateInterval(interval); err != nil {
			return TimeRange{}, err
		}
		return TimeRange{Start: now.Add(-dur), End: now, Interval: interval}, nil
	}

	if start.IsZero() || end.IsZero() {
		return TimeRange{}, apperrors.NewValidation("either a preset or explicit start and end timestamps are required", nil)
	}
	start, end = start.UTC(), end.UTC()
	if !end.After(start) {
		return TimeRange{}, apperrors.NewValidation("end must be after start", nil)
	}
	if end.Sub(start) > MaxQueryWindow {
		return TimeRange{}, apperrors.NewValidation(fmt.Sprintf("requested range %s exceeds the maximum query window %s", end.Sub(start), MaxQueryWindow), nil)
	}
	if interval == "" {
		interval = intervalForDuration(end.Sub(start))
	}
	if err := validateInterval(interval); err != nil {
		return TimeRange{}, err
	}
	return TimeRange{Start: start, End: end, Interval: interval}, nil
}

func intervalForDuration(d time.Duration) string {
	switch {
	case d <= 24*time.Hour:
		return "hour"
	case d <= 30*24*time.Hour:
		return "day"
	default:
		return "week"
	}
}

var validIntervals = map[string]bool{"hour": true, "day": true, "week": true}

func validateInterval(interval string) error {
	if !validIntervals[interval] {
		return apperrors.NewValidation(fmt.Sprintf("unrecognized interval %q — must be one of hour, day, week", interval), nil)
	}
	return nil
}
