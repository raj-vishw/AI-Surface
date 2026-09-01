package network

import (
	"reflect"
	"strings"
	"testing"
)

func TestParsePorts_Single(t *testing.T) {
	got, err := ParsePorts("80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []int{80}) {
		t.Errorf("got %v, want [80]", got)
	}
}

func TestParsePorts_List(t *testing.T) {
	got, err := ParsePorts("80,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []int{80, 443}) {
		t.Errorf("got %v, want [80 443]", got)
	}
}

func TestParsePorts_Range(t *testing.T) {
	got, err := ParsePorts("8000-8010")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 11 || got[0] != 8000 || got[len(got)-1] != 8010 {
		t.Errorf("got %v, want 11 ports from 8000 to 8010", got)
	}
}

func TestParsePorts_MixedWithDuplicates(t *testing.T) {
	// phase4.md §8's exact example.
	got, err := ParsePorts("80,80,443,8000-8002,8001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{80, 443, 8000, 8001, 8002}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePorts_DuplicatesAcrossListAndRange(t *testing.T) {
	got, err := ParsePorts("8000,8000-8002,8002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{8000, 8001, 8002}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePorts_SortedRegardlessOfInputOrder(t *testing.T) {
	got, err := ParsePorts("443,80,8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{80, 443, 8080}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePorts_InvalidPortZero(t *testing.T) {
	if _, err := ParsePorts("0"); err == nil {
		t.Fatal("expected an error for port 0")
	}
}

func TestParsePorts_InvalidPortNegative(t *testing.T) {
	if _, err := ParsePorts("-1"); err == nil {
		t.Fatal("expected an error for a negative port")
	}
}

func TestParsePorts_InvalidPortTooLarge(t *testing.T) {
	if _, err := ParsePorts("65536"); err == nil {
		t.Fatal("expected an error for a port above 65535")
	}
}

func TestParsePorts_NonNumeric(t *testing.T) {
	if _, err := ParsePorts("abc"); err == nil {
		t.Fatal("expected an error for a non-numeric port")
	}
}

func TestParsePorts_MalformedRange(t *testing.T) {
	if _, err := ParsePorts("8000-"); err == nil {
		t.Fatal("expected an error for a malformed range")
	}
	if _, err := ParsePorts("-8000"); err == nil {
		t.Fatal("expected an error for a malformed range")
	}
}

func TestParsePorts_ReversedRange(t *testing.T) {
	_, err := ParsePorts("8000-7000")
	if err == nil {
		t.Fatal("expected an error for a reversed range (start > end)")
	}
	// phase4.md §9: errors must be actionable, naming the problem.
	if got := err.Error(); !strings.Contains(got, "start port must not exceed end port") {
		t.Errorf("error message = %q, want it to explain the reversed range", got)
	}
}

func TestParsePorts_EmptyValue(t *testing.T) {
	if _, err := ParsePorts(""); err == nil {
		t.Fatal("expected an error for an empty port specification")
	}
	if _, err := ParsePorts("80,,443"); err == nil {
		t.Fatal("expected an error for an empty value between commas")
	}
}

func TestParsePorts_NeverSilentlyCorrects(t *testing.T) {
	// A malformed range must error, not silently swap start/end or clamp
	// out-of-range values (phase4.md §9).
	for _, spec := range []string{"8000-7000", "0-100", "100-70000", "abc-100"} {
		if _, err := ParsePorts(spec); err == nil {
			t.Errorf("ParsePorts(%q) should have errored, not silently corrected", spec)
		}
	}
}
