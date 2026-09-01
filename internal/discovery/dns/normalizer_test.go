package dns

import "testing"

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"lowercased and trailing dot stripped", "API.Example.Test.", "api.example.test", false},
		{"already normalized", "api.example.test", "api.example.test", false},
		{"IDN converted to punycode", "café.example.test", "xn--caf-dma.example.test", false},
		{"leading/trailing whitespace trimmed", "  api.example.test  ", "api.example.test", false},
		{"single label", "localhost", "localhost", false},
		{"empty name", "", "", true},
		{"empty label", "a..b", "", true},
		{"label too long", string(make([]byte, 64)) + ".example.test", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeName(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeName(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeName(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeName_NameTooLong(t *testing.T) {
	// 4 labels of 63 chars each plus dots comfortably exceeds 253.
	label := ""
	for i := 0; i < 63; i++ {
		label += "a"
	}
	long := label + "." + label + "." + label + "." + label + ".test"
	if _, err := NormalizeName(long); err == nil {
		t.Errorf("NormalizeName(253+ char name) = nil error, want error")
	}
}

func TestJoinLabel(t *testing.T) {
	got := JoinLabel("api", "example.test")
	want := "api.example.test"
	if got != want {
		t.Errorf("JoinLabel() = %q, want %q", got, want)
	}
}
