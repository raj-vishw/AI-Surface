package analytics

import (
	"testing"
	"time"
)

func TestResolveRange_Presets(t *testing.T) {
	cases := []struct {
		preset       RangePreset
		wantInterval string
	}{
		{Range24h, "hour"},
		{Range7d, "day"},
		{Range30d, "day"},
		{Range90d, "week"},
	}
	for _, c := range cases {
		r, err := ResolveRange(c.preset, time.Time{}, time.Time{}, "")
		if err != nil {
			t.Fatalf("ResolveRange(%s): %v", c.preset, err)
		}
		if r.Interval != c.wantInterval {
			t.Errorf("ResolveRange(%s).Interval = %q, want %q", c.preset, r.Interval, c.wantInterval)
		}
		if !r.End.After(r.Start) {
			t.Errorf("ResolveRange(%s): End must be after Start", c.preset)
		}
	}
}

func TestResolveRange_RejectsUnknownPreset(t *testing.T) {
	if _, err := ResolveRange("last week", time.Time{}, time.Time{}, ""); err == nil {
		t.Fatal("expected an error for an unrecognized preset")
	}
}

func TestResolveRange_RejectsEndBeforeStart(t *testing.T) {
	end := time.Now()
	start := end.Add(time.Hour) // after end
	if _, err := ResolveRange("", start, end, ""); err == nil {
		t.Fatal("expected an error when end is before start")
	}
}

func TestResolveRange_RejectsExcessiveWindow(t *testing.T) {
	end := time.Now()
	start := end.Add(-365 * 24 * time.Hour)
	if _, err := ResolveRange("", start, end, ""); err == nil {
		t.Fatal("expected an error for a window exceeding MaxQueryWindow")
	}
}

func TestResolveRange_RejectsInvalidInterval(t *testing.T) {
	if _, err := ResolveRange(Range7d, time.Time{}, time.Time{}, "fortnight"); err == nil {
		t.Fatal("expected an error for an invalid interval override")
	}
}

func TestResolveRange_ExplicitIntervalOverridesDefault(t *testing.T) {
	r, err := ResolveRange(Range24h, time.Time{}, time.Time{}, "day")
	if err != nil {
		t.Fatalf("ResolveRange: %v", err)
	}
	if r.Interval != "day" {
		t.Errorf("Interval = %q, want explicit override %q", r.Interval, "day")
	}
}

func TestResolveRange_RequiresPresetOrExplicitRange(t *testing.T) {
	if _, err := ResolveRange("", time.Time{}, time.Time{}, ""); err == nil {
		t.Fatal("expected an error when neither a preset nor start/end is given")
	}
}

func TestResolveRange_TimestampsAreUTC(t *testing.T) {
	loc := time.FixedZone("UTC+5", 5*60*60)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, loc)
	end := time.Date(2026, 1, 2, 0, 0, 0, 0, loc)
	r, err := ResolveRange("", start, end, "")
	if err != nil {
		t.Fatalf("ResolveRange: %v", err)
	}
	if r.Start.Location() != time.UTC || r.End.Location() != time.UTC {
		t.Error("ResolveRange did not normalize timestamps to UTC")
	}
}
