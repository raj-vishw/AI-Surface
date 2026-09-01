package pagination

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCursor_RoundTrip(t *testing.T) {
	c := Cursor{CreatedAt: time.Now().UTC().Truncate(time.Nanosecond), ID: uuid.New()}
	encoded := c.Encode()

	decoded, err := DecodeCursor(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decoded.CreatedAt.Equal(c.CreatedAt) || decoded.ID != c.ID {
		t.Errorf("round trip mismatch: got %+v, want %+v", decoded, c)
	}
}

func TestDecodeCursor_Empty(t *testing.T) {
	decoded, err := DecodeCursor("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decoded.CreatedAt.IsZero() || decoded.ID != uuid.Nil {
		t.Errorf("expected zero Cursor for empty input, got %+v", decoded)
	}
}

func TestDecodeCursor_Invalid(t *testing.T) {
	if _, err := DecodeCursor("not-a-valid-cursor!!!"); err == nil {
		t.Fatal("expected an error for invalid cursor encoding")
	}
}

func TestParams_ResolveLimit(t *testing.T) {
	cases := []struct {
		limit    int
		expected int
	}{
		{0, DefaultLimit},
		{-5, DefaultLimit},
		{10, 10},
		{MaxLimit + 100, MaxLimit},
	}
	for _, tc := range cases {
		p := Params{Limit: tc.limit}
		if got := p.ResolveLimit(); got != tc.expected {
			t.Errorf("Params{Limit: %d}.ResolveLimit() = %d, want %d", tc.limit, got, tc.expected)
		}
	}
}
