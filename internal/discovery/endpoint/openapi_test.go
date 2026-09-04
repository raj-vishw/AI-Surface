package endpoint

import "testing"

const testOpenAPIJSON = `{
  "openapi": "3.0.0",
  "info": {"title": "Test API", "version": "1.2.3"},
  "paths": {
    "/api/users": {
      "get": {"operationId": "listUsers", "summary": "List users", "tags": ["users"], "parameters": [{"name": "page", "in": "query"}]},
      "post": {"operationId": "createUser", "requestBody": {"content": {"application/json": {}}}}
    },
    "/api/users/{id}": {
      "get": {"operationId": "getUser", "parameters": [{"name": "id", "in": "path"}]},
      "delete": {"operationId": "deleteUser"}
    }
  },
  "components": {
    "securitySchemes": {
      "bearerAuth": {"type": "http", "scheme": "bearer"}
    }
  }
}`

const testSwaggerJSON = `{
  "swagger": "2.0",
  "info": {"version": "2.0.1"},
  "paths": {
    "/pets": {
      "get": {"operationId": "listPets"}
    }
  },
  "securityDefinitions": {
    "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
  }
}`

const testOpenAPIYAML = `
openapi: 3.0.0
info:
  version: 1.0.0
paths:
  /v1/models:
    get:
      operationId: listModels
`

func TestParseOpenAPI_JSON(t *testing.T) {
	doc, err := ParseOpenAPI([]byte(testOpenAPIJSON))
	if err != nil {
		t.Fatalf("ParseOpenAPI: %v", err)
	}
	if doc.Version != "1.2.3" {
		t.Errorf("Version = %q, want 1.2.3", doc.Version)
	}
	if doc.IsSwagger {
		t.Errorf("IsSwagger = true, want false")
	}
	if len(doc.Operations) != 4 {
		t.Fatalf("len(Operations) = %d, want 4", len(doc.Operations))
	}

	var getUsers, deleteUser *OpenAPIOperation
	for i, op := range doc.Operations {
		if op.Path == "/api/users" && op.Method == "GET" {
			getUsers = &doc.Operations[i]
		}
		if op.Path == "/api/users/{id}" && op.Method == "DELETE" {
			deleteUser = &doc.Operations[i]
		}
	}
	if getUsers == nil {
		t.Fatal("expected GET /api/users")
	}
	if getUsers.OperationID != "listUsers" || len(getUsers.Tags) != 1 || getUsers.Tags[0] != "users" {
		t.Errorf("GET /api/users = %+v, unexpected shape", getUsers)
	}
	if len(getUsers.ParameterNames) != 1 || getUsers.ParameterNames[0].Name != "page" {
		t.Errorf("GET /api/users params = %+v, want [page]", getUsers.ParameterNames)
	}
	if deleteUser == nil {
		t.Fatal("expected DELETE /api/users/{id}")
	}
	if deleteUser.OperationID != "deleteUser" {
		t.Errorf("DELETE operationId = %q, want deleteUser", deleteUser.OperationID)
	}

	if len(doc.SecuritySchemeTypes) != 1 || doc.SecuritySchemeTypes[0] != "bearer" {
		t.Errorf("SecuritySchemeTypes = %v, want [bearer]", doc.SecuritySchemeTypes)
	}
}

func TestParseOpenAPI_Swagger(t *testing.T) {
	doc, err := ParseOpenAPI([]byte(testSwaggerJSON))
	if err != nil {
		t.Fatalf("ParseOpenAPI: %v", err)
	}
	if !doc.IsSwagger {
		t.Errorf("IsSwagger = false, want true")
	}
	if doc.Version != "2.0.1" {
		t.Errorf("Version = %q, want 2.0.1", doc.Version)
	}
	if len(doc.Operations) != 1 || doc.Operations[0].Path != "/pets" {
		t.Fatalf("Operations = %+v, want [GET /pets]", doc.Operations)
	}
	if len(doc.SecuritySchemeTypes) != 1 || doc.SecuritySchemeTypes[0] != "apiKey" {
		t.Errorf("SecuritySchemeTypes = %v, want [apiKey]", doc.SecuritySchemeTypes)
	}
}

func TestParseOpenAPI_YAML(t *testing.T) {
	doc, err := ParseOpenAPI([]byte(testOpenAPIYAML))
	if err != nil {
		t.Fatalf("ParseOpenAPI(YAML): %v", err)
	}
	if doc.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", doc.Version)
	}
	if len(doc.Operations) != 1 || doc.Operations[0].Path != "/v1/models" || doc.Operations[0].OperationID != "listModels" {
		t.Fatalf("Operations = %+v, want [GET /v1/models listModels]", doc.Operations)
	}
}

func TestParseOpenAPI_NeverStoresCredentials(t *testing.T) {
	doc, err := ParseOpenAPI([]byte(testOpenAPIJSON))
	if err != nil {
		t.Fatalf("ParseOpenAPI: %v", err)
	}
	// SecuritySchemeTypes records only "bearer" — never any actual token
	// or key value (the source document has none to leak, by design of
	// what OpenAPI's securitySchemes object contains, but this asserts
	// the extraction path never introduces one either).
	for _, s := range doc.SecuritySchemeTypes {
		if s != "bearer" && s != "apiKey" && s != "oauth2" && s != "basic" && s != "http" {
			t.Errorf("unexpected security scheme value leaked: %q", s)
		}
	}
}

func TestParseOpenAPI_Malformed(t *testing.T) {
	if _, err := ParseOpenAPI([]byte("not json or yaml: [[[")); err == nil {
		t.Error("expected an error for a malformed document")
	}
}
