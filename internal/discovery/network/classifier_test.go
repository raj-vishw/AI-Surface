package network

import "testing"

func TestClassifyPort_HTTP(t *testing.T) {
	if got := classifyPort(80); got != ServiceHTTP {
		t.Errorf("classifyPort(80) = %s, want %s", got, ServiceHTTP)
	}
	if got := classifyPort(8080); got != ServiceHTTP {
		t.Errorf("classifyPort(8080) = %s, want %s", got, ServiceHTTP)
	}
}

func TestClassifyPort_HTTPS(t *testing.T) {
	if got := classifyPort(443); got != ServiceHTTPS {
		t.Errorf("classifyPort(443) = %s, want %s", got, ServiceHTTPS)
	}
}

func TestClassifyPort_SSH(t *testing.T) {
	if got := classifyPort(22); got != ServiceSSH {
		t.Errorf("classifyPort(22) = %s, want %s", got, ServiceSSH)
	}
}

func TestClassifyPort_Unknown(t *testing.T) {
	// An arbitrary high port with no conventional association.
	if got := classifyPort(54321); got != ServiceUnknown {
		t.Errorf("classifyPort(54321) = %s, want %s", got, ServiceUnknown)
	}
}

func TestClassifyPort_IsConservativeNotDefinitive(t *testing.T) {
	// phase4.md §21: "a port number alone should not be treated as
	// definitive proof". This is documented, not mechanically testable as
	// a boolean — but every classification must be a Service value, never
	// something claiming certainty (no "CONFIRMED_SSH" variant exists).
	for _, port := range []int{22, 80, 443, 3306} {
		service := classifyPort(port)
		if service == "" {
			t.Errorf("classifyPort(%d) returned empty Service", port)
		}
	}
}

func TestAIServiceCandidate_ConfiguredPort(t *testing.T) {
	candidate, reason := aiServiceCandidate(11434, []int{11434, 5000, 8000, 8080, 8888})
	if !candidate {
		t.Error("expected 11434 to be an AI service candidate")
	}
	if reason != "configured_ai_port" {
		t.Errorf("reason = %q, want \"configured_ai_port\"", reason)
	}
}

func TestAIServiceCandidate_OrdinaryPortNotInherentlyAI(t *testing.T) {
	// phase4.md §7/§24: a reachable port is never proof of an AI service;
	// port 80 is not on any AI candidate list by default.
	candidate, _ := aiServiceCandidate(80, []int{11434, 5000, 8000, 8080, 8888})
	if candidate {
		t.Error("expected port 80 to not be an AI candidate")
	}
}

func TestAIServiceCandidate_CustomConfiguredPort(t *testing.T) {
	candidate, reason := aiServiceCandidate(23456, []int{23456})
	if !candidate {
		t.Error("expected a custom-configured AI candidate port to be recognized")
	}
	if reason != "configured_ai_port" {
		t.Errorf("reason = %q, want \"configured_ai_port\"", reason)
	}
}

func TestHTTPCandidate(t *testing.T) {
	if !httpCandidate(8080, []int{80, 443, 8000, 8080, 8443}) {
		t.Error("expected 8080 to be an HTTP candidate")
	}
	if httpCandidate(22, []int{80, 443, 8000, 8080, 8443}) {
		t.Error("expected 22 to not be an HTTP candidate")
	}
}

func TestClassificationIndicator_EmptyForUnknown(t *testing.T) {
	if got := classificationIndicator(54321, ServiceUnknown); got != "" {
		t.Errorf("expected no indicator for UNKNOWN, got %q", got)
	}
}
