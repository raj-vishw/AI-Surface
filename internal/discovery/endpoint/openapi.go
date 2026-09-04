package endpoint

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// openAPIMethods are the HTTP-method keys recognized inside a paths
// object — every other key under a path item (parameters, summary,
// description, $ref, ...) is not an operation and is skipped.
var openAPIMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true,
	"delete": true, "head": true, "options": true,
}

// OpenAPIOperation is one documented (path, method) operation, extracted
// safely (phase7.md §19/§48): path, method, operationId, summary, tags,
// parameter names, and content types only — never example values,
// authentication tokens, or credentials.
type OpenAPIOperation struct {
	Path                 string
	Method               string
	OperationID          string
	Summary              string
	Tags                 []string
	ParameterNames       []Parameter
	RequestContentTypes  []string
	ResponseContentTypes []string
}

// OpenAPIDocument is the safely-extracted content of one OpenAPI/Swagger
// document (phase7.md §19/§20/§21/§48).
type OpenAPIDocument struct {
	// Version is info.version if present — the API's own declared
	// version, never guessed from anything else (phase7.md §17).
	Version    string
	IsSwagger  bool // true for a Swagger 2.0 document (swagger: "2.0"), false for OpenAPI 3.x
	Operations []OpenAPIOperation
	// SecuritySchemeTypes names only the *kind* of authentication a
	// document declares (phase7.md §21: "record only the existence/type
	// of the authentication mechanism... do NOT extract or store
	// credentials") — e.g. "bearer", "apiKey", "oauth2", "basic". Never
	// a scheme's actual key/secret/token value, which OpenAPI documents
	// never legitimately contain anyway (they describe the mechanism,
	// not a live credential) — this field exists purely to record which
	// mechanisms are documented as present.
	SecuritySchemeTypes []string
}

// ParseOpenAPI parses body as an OpenAPI 3.x or Swagger 2.0 document —
// JSON first, then YAML as a best-effort fallback (both are valid
// document formats per the spec; this project's YAML support reuses
// gopkg.in/yaml.v3, already a dependency — no new library was added for
// this). It extracts only the safe structural metadata OpenAPIDocument
// documents; it never executes any operation the document describes
// (phase7.md §19: "Do not execute any API operation merely because it
// appears in the specification").
func ParseOpenAPI(body []byte) (OpenAPIDocument, error) {
	doc, err := decodeGenericDocument(body)
	if err != nil {
		return OpenAPIDocument{}, fmt.Errorf("parsing OpenAPI/Swagger document: %w", err)
	}
	return extractOpenAPI(doc), nil
}

func decodeGenericDocument(body []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err == nil {
		return m, nil
	}
	if err := yaml.Unmarshal(body, &m); err == nil {
		return m, nil
	}
	return nil, fmt.Errorf("not valid JSON or YAML")
}

func extractOpenAPI(doc map[string]any) OpenAPIDocument {
	result := OpenAPIDocument{}

	if _, ok := doc["swagger"]; ok {
		result.IsSwagger = true
	}

	if info, ok := asMap(doc["info"]); ok {
		if v, ok := info["version"].(string); ok {
			result.Version = v
		}
	}

	paths, _ := asMap(doc["paths"])
	pathNames := make([]string, 0, len(paths))
	for p := range paths {
		pathNames = append(pathNames, p)
	}
	sort.Strings(pathNames) // deterministic output order

	for _, path := range pathNames {
		item, ok := asMap(paths[path])
		if !ok {
			continue
		}
		pathLevelParams := extractParameters(item["parameters"])

		methodNames := make([]string, 0, len(item))
		for m := range item {
			methodNames = append(methodNames, m)
		}
		sort.Strings(methodNames)

		for _, method := range methodNames {
			if !openAPIMethods[method] {
				continue
			}
			op, ok := asMap(item[method])
			if !ok {
				continue
			}
			operation := OpenAPIOperation{
				Path: path, Method: strings.ToUpper(method),
			}
			if id, ok := op["operationId"].(string); ok {
				operation.OperationID = id
			}
			if summary, ok := op["summary"].(string); ok {
				operation.Summary = summary
			}
			operation.Tags = asStringSlice(op["tags"])
			operation.ParameterNames = append(pathLevelParams, extractParameters(op["parameters"])...)
			operation.RequestContentTypes = extractContentTypes(op["requestBody"])
			operation.ResponseContentTypes = extractResponseContentTypes(op["responses"])
			result.Operations = append(result.Operations, operation)
		}
	}

	result.SecuritySchemeTypes = extractSecuritySchemes(doc)
	return result
}

// extractParameters reads a parameters array (OpenAPI 3 / Swagger 2 share
// this shape: a list of {name, in, ...} objects) into Parameter values —
// names only, never any "example"/"default" value the document might
// carry (phase7.md §48).
func extractParameters(raw any) []Parameter {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []Parameter
	for _, item := range list {
		p, ok := asMap(item)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		in, _ := p["in"].(string)
		if name == "" {
			continue
		}
		location := "query"
		switch in {
		case "path":
			location = "path"
		case "query", "header", "cookie":
			location = "query"
		}
		out = append(out, Parameter{Name: name, Location: location})
	}
	return out
}

// extractContentTypes reads requestBody.content's keys (OpenAPI 3 only —
// Swagger 2 has no requestBody; its equivalent is a body parameter with
// no distinct content-type list, so this returns nil for Swagger 2 docs,
// which is accurate, not a bug).
func extractContentTypes(raw any) []string {
	body, ok := asMap(raw)
	if !ok {
		return nil
	}
	content, ok := asMap(body["content"])
	if !ok {
		return nil
	}
	return mapKeysSorted(content)
}

// extractResponseContentTypes collects every distinct content-type key
// across every documented response's content object.
func extractResponseContentTypes(raw any) []string {
	responses, ok := asMap(raw)
	if !ok {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, v := range responses {
		resp, ok := asMap(v)
		if !ok {
			continue
		}
		content, ok := asMap(resp["content"])
		if !ok {
			continue
		}
		for _, ct := range mapKeysSorted(content) {
			if !seen[ct] {
				seen[ct] = true
				out = append(out, ct)
			}
		}
	}
	sort.Strings(out)
	return out
}

// extractSecuritySchemes reads OpenAPI 3's components.securitySchemes or
// Swagger 2's securityDefinitions and returns the distinct set of scheme
// *types* declared — never any credential value (phase7.md §21).
func extractSecuritySchemes(doc map[string]any) []string {
	var schemes map[string]any
	if components, ok := asMap(doc["components"]); ok {
		schemes, _ = asMap(components["securitySchemes"])
	}
	if schemes == nil {
		schemes, _ = asMap(doc["securityDefinitions"])
	}
	if schemes == nil {
		return nil
	}

	seen := make(map[string]bool)
	var out []string
	for _, v := range schemes {
		scheme, ok := asMap(v)
		if !ok {
			continue
		}
		typ, _ := scheme["type"].(string)
		label := typ
		if typ == "http" {
			if sub, ok := scheme["scheme"].(string); ok && sub != "" {
				label = sub // "bearer", "basic"
			}
		}
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func asStringSlice(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func mapKeysSorted(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
