package dns

import (
	"strings"
	"testing"
)

func TestSanitizeTXTValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"api_key redacted", "api_key=sk-live-abc123", "api_key=[REDACTED]"},
		{"password with colon redacted", "password: hunter2", "password: [REDACTED]"},
		{"legitimate SPF record untouched", "v=spf1 -all", "v=spf1 -all"},
		{"legitimate DMARC record untouched", "v=DMARC1; p=reject; rua=mailto:dmarc@example.test", "v=DMARC1; p=reject; rua=mailto:dmarc@example.test"},
		{"multiple key-value pairs, only sensitive one redacted", "region=us-east token=abc123", "region=us-east token=[REDACTED]"},
		{"case-insensitive key match", "API_KEY=abc123", "API_KEY=[REDACTED]"},
		{"plain text with no key=value shape untouched", "just some verification text", "just some verification text"},
		{"authorization key redacted (only the first token — value is \\S+)", "authorization=Bearer abc.def.ghi", "authorization=[REDACTED] abc.def.ghi"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeTXTValue(tc.value); got != tc.want {
				t.Errorf("SanitizeTXTValue(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestSanitizeTXTValue_NeverLeaksSecretIntoOutput(t *testing.T) {
	value := "verification=ok secret=sk-live-abc123xyz"
	got := SanitizeTXTValue(value)
	if strings.Contains(got, "sk-live-abc123xyz") {
		t.Errorf("SanitizeTXTValue leaked the secret value: %q", got)
	}
	if !strings.Contains(got, "verification=ok") {
		t.Errorf("SanitizeTXTValue over-redacted a non-sensitive pair: %q", got)
	}
}
