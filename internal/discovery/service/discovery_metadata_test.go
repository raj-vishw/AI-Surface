package service

import (
	"testing"

	"ai-recon-platform/internal/discovery/model"
	domainasset "ai-recon-platform/internal/domain/asset"
)

func TestBuildMetadata_CookieAttributes(t *testing.T) {
	result := model.Result{
		Cookies: []model.CookieAttribute{
			{Name: "session", Secure: true, HTTPOnly: true, SameSite: "Strict"},
			{Name: "insecure", Secure: false, HTTPOnly: false, SameSite: ""},
		},
	}

	metadata := buildMetadata(result, true)

	cookies, ok := metadata["cookie_attributes"].([]any)
	if !ok || len(cookies) != 2 {
		t.Fatalf("expected 2 cookie_attributes entries, got %#v", metadata["cookie_attributes"])
	}
	first, ok := cookies[0].(map[string]any)
	if !ok || first["name"] != "session" || first["secure"] != true || first["httponly"] != true || first["samesite"] != "Strict" {
		t.Errorf("unexpected first cookie entry: %#v", cookies[0])
	}
}

func TestBuildMetadata_CookieAttributesSurviveSanitization(t *testing.T) {
	// This is the real point of the naming choice: "cookie_attributes"
	// must not be swallowed by asset.SanitizeMetadata's "cookie"
	// substring redaction, unlike a raw "cookies" key would be.
	result := model.Result{
		Cookies: []model.CookieAttribute{{Name: "session", Secure: true, HTTPOnly: true, SameSite: "Lax"}},
	}
	metadata := buildMetadata(result, true)

	sanitized := domainasset.SanitizeMetadata(metadata)
	cookies, ok := sanitized["cookie_attributes"].([]any)
	if !ok || len(cookies) != 1 {
		t.Fatalf("expected cookie_attributes to survive sanitization untouched, got %#v", sanitized["cookie_attributes"])
	}
}
