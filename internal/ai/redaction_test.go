package ai

import "testing"

func TestRedact_RemovesSecretShapes(t *testing.T) {
	cases := []string{
		"Authorization: Bearer sk-abcdefghijklmnopqrstuvwx",
		"api_key: 1234567890abcdef",
		"password=SuperSecret123",
		"AWS key AKIAABCDEFGHIJKLMNOP found in config",
		"token gho_1234567890abcdefghijklmnopqrstuvwxyz",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...\n-----END RSA PRIVATE KEY-----",
		"Cookie: session=abcde12345",
	}
	for _, c := range cases {
		got := Redact(c)
		if got == c {
			t.Errorf("Redact(%q) did not change input — secret pattern not matched", c)
		}
	}
}

func TestRedact_LeavesOrdinaryTextAlone(t *testing.T) {
	s := "The asset example.com returned HTTP 403 on /admin"
	if got := Redact(s); got != s {
		t.Errorf("Redact modified ordinary text: got %q, want %q", got, s)
	}
}

func TestRedactFact_RedactsSummaryAndAttributes(t *testing.T) {
	f := Fact{
		Summary:    "Response contained password=hunter2",
		Attributes: map[string]string{"header": "Authorization: Bearer sk-abcdefghijklmnopqrstuvwx"},
	}
	got := RedactFact(f)
	if got.Summary == f.Summary {
		t.Error("RedactFact did not redact Summary")
	}
	if got.Attributes["header"] == f.Attributes["header"] {
		t.Error("RedactFact did not redact Attributes")
	}
}
