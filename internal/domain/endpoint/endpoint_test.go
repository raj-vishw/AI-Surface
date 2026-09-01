package endpoint

import (
	"testing"

	"github.com/google/uuid"
)

func TestValidate_ValidEndpoint(t *testing.T) {
	e := Endpoint{
		AssetID: uuid.New(),
		URL:     "https://example.com/api",
		Method:  MethodGet,
		Status:  StatusDiscovered,
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid endpoint, got: %v", err)
	}
}

func TestValidate_MissingAssetID(t *testing.T) {
	e := Endpoint{URL: "https://example.com/api", Method: MethodGet}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error for missing asset id")
	}
}

func TestValidate_UnrecognizedMethod(t *testing.T) {
	e := Endpoint{AssetID: uuid.New(), URL: "https://example.com/api", Method: "TRACE"}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error for unrecognized method")
	}
}

func TestValidate_MalformedURL(t *testing.T) {
	e := Endpoint{AssetID: uuid.New(), URL: "not a url", Method: MethodGet}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestValidate_InvalidStatusCode(t *testing.T) {
	code := 999
	e := Endpoint{AssetID: uuid.New(), URL: "https://example.com/api", Method: MethodGet, StatusCode: &code}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error for invalid status code")
	}
}

func TestIdentity_DiffersByMethod(t *testing.T) {
	get := Identity("https", "example.com", 443, "/api", MethodGet)
	post := Identity("https", "example.com", 443, "/api", MethodPost)
	if get == post {
		t.Error("GET and POST to the same URL must have different identities")
	}
}
