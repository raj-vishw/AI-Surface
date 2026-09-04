package investigation

import (
	"testing"

	domainfinding "ai-recon-platform/internal/domain/finding"
	domaininvestigation "ai-recon-platform/internal/domain/investigation"
)

func TestMapFindingEvent(t *testing.T) {
	f := domainfinding.Finding{Title: "Missing HSTS"}

	cases := []struct {
		eventType domainfinding.EventType
		wantType  domaininvestigation.EventType
	}{
		{domainfinding.EventResolved, domaininvestigation.EventFindingResolved},
		{domainfinding.EventReopened, domaininvestigation.EventFindingReopened},
		{domainfinding.EventOpened, ""},
		{domainfinding.EventUpdated, ""},
	}
	for _, tc := range cases {
		got, _ := mapFindingEvent(domainfinding.Event{Type: tc.eventType}, f)
		if got != tc.wantType {
			t.Errorf("mapFindingEvent(%s) type = %q, want %q", tc.eventType, got, tc.wantType)
		}
	}
}
