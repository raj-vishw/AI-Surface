package asset

import "testing"

func TestSanitizeMetadata_RedactsSensitiveKeys(t *testing.T) {
	input := map[string]any{
		"server":             "nginx",
		"Authorization":      "Bearer abc123",
		"X-Api-Key":          "sk-live-abc",
		"session_token":      "xyz",
		"password":           "hunter2",
		"user_password_hash": "abc",
		"cookie":             "sessionid=1",
		"private_key":        "-----BEGIN KEY-----",
		"refresh_token":      "rtoken",
		"credential_bundle":  "abc",
	}
	out := SanitizeMetadata(input)

	sensitiveKeys := []string{
		"Authorization", "X-Api-Key", "session_token", "password",
		"user_password_hash", "cookie", "private_key", "refresh_token",
		"credential_bundle",
	}
	for _, key := range sensitiveKeys {
		if out[key] != redactedValue {
			t.Errorf("key %q = %v, want redacted", key, out[key])
		}
	}
	if out["server"] != "nginx" {
		t.Errorf("non-sensitive key %q was modified: %v", "server", out["server"])
	}
}

func TestSanitizeMetadata_RecursesIntoNestedObjects(t *testing.T) {
	input := map[string]any{
		"response": map[string]any{
			"headers": map[string]any{
				"Authorization": "Bearer secret",
				"Content-Type":  "application/json",
			},
		},
	}
	out := SanitizeMetadata(input)

	response, ok := out["response"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map, got %T", out["response"])
	}
	headers, ok := response["headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map, got %T", response["headers"])
	}
	if headers["Authorization"] != redactedValue {
		t.Errorf("nested Authorization = %v, want redacted", headers["Authorization"])
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("nested Content-Type was modified: %v", headers["Content-Type"])
	}
}

func TestSanitizeMetadata_RecursesIntoArrays(t *testing.T) {
	input := map[string]any{
		"cookies": []any{
			map[string]any{"name": "session", "value": "should-not-matter"},
			map[string]any{"Authorization": "secret"},
		},
	}
	out := SanitizeMetadata(input)

	// "cookies" itself matches the sensitive-key fragment "cookie" and is
	// redacted wholesale, which is correct — but verify the recursive case
	// separately with a non-matching container key.
	input2 := map[string]any{
		"headers_list": []any{
			map[string]any{"Authorization": "secret"},
		},
	}
	out2 := SanitizeMetadata(input2)
	list, ok := out2["headers_list"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("expected a one-element list, got %#v", out2["headers_list"])
	}
	entry, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("expected map entry, got %T", list[0])
	}
	if entry["Authorization"] != redactedValue {
		t.Errorf("Authorization inside array = %v, want redacted", entry["Authorization"])
	}

	if out["cookies"] != redactedValue {
		t.Errorf("key matching a sensitive fragment should redact the whole value, got %#v", out["cookies"])
	}
}

func TestSanitizeMetadata_NilInput(t *testing.T) {
	if SanitizeMetadata(nil) != nil {
		t.Error("SanitizeMetadata(nil) should return nil")
	}
}

func TestSanitizeMetadata_DoesNotMutateInput(t *testing.T) {
	input := map[string]any{"password": "hunter2"}
	_ = SanitizeMetadata(input)
	if input["password"] != "hunter2" {
		t.Error("SanitizeMetadata must not mutate its input")
	}
}

func TestSanitizeMetadata_CaseInsensitive(t *testing.T) {
	input := map[string]any{"PASSWORD": "hunter2", "ApiKey": "abc"}
	out := SanitizeMetadata(input)
	if out["PASSWORD"] != redactedValue || out["ApiKey"] != redactedValue {
		t.Errorf("expected case-insensitive redaction, got %#v", out)
	}
}
