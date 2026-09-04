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

// --- Phase 7 additions below: Classification/Confidence validation ---

func validEndpoint() Endpoint {
	return Endpoint{
		AssetID: uuid.New(), URL: "https://example.test/api/users", Method: MethodGet,
		Scheme: "https", Host: "example.test", Port: 443, Path: "/api/users",
		Classification: ClassificationAPI, Confidence: 0.9,
	}
}

func TestEndpoint_Validate_Valid(t *testing.T) {
	if err := validEndpoint().Validate(); err != nil {
		t.Errorf("expected valid, got: %v", err)
	}
}

func TestEndpoint_Validate_EmptyClassificationIsValid(t *testing.T) {
	e := validEndpoint()
	e.Classification = ""
	if err := e.Validate(); err != nil {
		t.Errorf("expected empty classification to be valid (means unset, not invalid), got: %v", err)
	}
}

func TestEndpoint_Validate_InvalidClassification(t *testing.T) {
	e := validEndpoint()
	e.Classification = "not_a_real_classification"
	if err := e.Validate(); err == nil {
		t.Error("expected an error for an invalid classification")
	}
}

func TestEndpoint_Validate_InvalidConfidence(t *testing.T) {
	e := validEndpoint()
	e.Confidence = 1.5
	if err := e.Validate(); err == nil {
		t.Error("expected an error for out-of-range confidence")
	}
}

func TestClassification_Valid(t *testing.T) {
	for _, c := range []Classification{
		ClassificationPage, ClassificationAPI, ClassificationGraphQL, ClassificationOpenAPI,
		ClassificationSwagger, ClassificationAuth, ClassificationStatic, ClassificationAsset,
		ClassificationDocumentation, ClassificationSitemap, ClassificationRobots,
		ClassificationWebSocketCandidate, ClassificationUnknown,
	} {
		if !c.Valid() {
			t.Errorf("Classification %q should be valid", c)
		}
	}
	if Classification("bogus").Valid() {
		t.Error("expected an unrecognized classification to be invalid")
	}
}
