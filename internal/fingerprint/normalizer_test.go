package fingerprint

import "testing"

func TestNormalizeTechnology(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nginx", "nginx"},
		{"Nginx", "nginx"},
		{"NGINX", "nginx"},
		{"nginx/1.25.3", "nginx"},
		{"nginx web server", "nginx"},
		{"Next", "Next.js"},
		{"next.js", "Next.js"},
		{"nextjs", "Next.js"},
		{"NextJS", "Next.js"},
		{"react.js", "React"},
		{"", ""},
		{"  nginx  ", "nginx"},
		{"SomeUnknownThing", "SomeUnknownThing"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := NormalizeTechnology(tc.input); got != tc.want {
				t.Errorf("NormalizeTechnology(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeTechnology_UnknownPreservesCasing(t *testing.T) {
	got := NormalizeTechnology("MyCustomThing")
	if got != "MyCustomThing" {
		t.Errorf("NormalizeTechnology(unknown) = %q, want original casing preserved", got)
	}
}
