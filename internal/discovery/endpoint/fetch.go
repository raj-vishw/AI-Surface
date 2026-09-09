package endpoint

import (
	"context"
	"strings"
	"time"

	domainendpoint "ai-surface-platform/internal/domain/endpoint"
	apperrors "ai-surface-platform/internal/errors"
)

// unfetchedResult builds a Result for a candidate that is recorded
// without ever being requested — a non-GET method (phase7.md §30), or a
// documented-only OpenAPI operation the crawl never independently
// reached. Classification is derived from path shape alone (no content
// type available, since nothing was fetched).
func unfetchedResult(cand Candidate, norm domainendpoint.Normalized) Result {
	identity := applyPathTemplate(norm)
	class, apiType, apiVersion := Classify(identity.Path, "")
	if IsAICandidatePath(identity.Path) {
		apiType = AIAPIType
	}
	r := Result{
		URL: identity.URL, Scheme: identity.Scheme, Host: identity.Host, Port: identity.Port,
		Path: identity.Path, QueryPattern: norm.QueryPattern, Method: strings.ToUpper(cand.Method),
		Classification: class, APIType: apiType, APIVersion: apiVersion,
		Sources: []string{cand.Source}, Confidence: cand.Confidence,
		Documented: cand.Documented, Inferred: cand.Inferred,
		Parameters: append(cand.Parameters, parametersFromQueryPattern(norm.QueryPattern)...),
		Evidence:   map[string]string{},
		ObservedAt: time.Now().UTC(),
	}
	if cand.Evidence != "" {
		r.Evidence[cand.Source] = cand.Evidence
	}
	return r
}

// fetchAndParse issues exactly one GET request for cand (already
// scope-validated and normalized as norm) and, on success, dispatches to
// the appropriate content parser (phase7.md §28): HTML -> links/forms/
// scripts, JavaScript -> static route extraction, everything else ->
// recorded with no further extraction. It never executes any script and
// never sends a non-GET request (enforced by the caller, fetchFrontier,
// before this is ever invoked).
func (c *Crawler) fetchAndParse(ctx context.Context, cand Candidate, norm domainendpoint.Normalized) (Result, []Candidate, int, error) {
	resp, err := c.client.Get(ctx, norm.URL, nil)
	if err != nil {
		return c.errorResult(cand, norm, err), nil, 0, err
	}

	identity := applyPathTemplate(norm)
	statusCode := resp.StatusCode
	contentLength := resp.BodySize
	class, apiType, apiVersion := Classify(identity.Path, resp.ContentType)
	if IsAICandidatePath(identity.Path) {
		apiType = AIAPIType
	}

	result := Result{
		URL: identity.URL, Scheme: identity.Scheme, Host: identity.Host, Port: identity.Port,
		Path: identity.Path, QueryPattern: norm.QueryPattern, Method: "GET",
		StatusCode: &statusCode, ContentType: resp.ContentType, ContentLength: &contentLength,
		ResponseHash:   resp.BodySHA256,
		Classification: class, APIType: apiType, APIVersion: apiVersion,
		Sources:    []string{cand.Source},
		Confidence: mergeObservedConfidence(cand.Confidence),
		Observed:   true, Documented: cand.Documented, Inferred: cand.Inferred,
		Parameters: append(cand.Parameters, parametersFromQueryPattern(norm.QueryPattern)...),
		Evidence:   map[string]string{},
		ObservedAt: time.Now().UTC(),
	}
	if cand.Evidence != "" {
		result.Evidence[cand.Source] = cand.Evidence
	}

	var discovered []Candidate
	switch {
	case looksLikeHTML(resp.ContentType) || (resp.ContentType == "" && looksLikeHTMLBody(resp.Body)):
		parsed := ParseHTML(resp.Body)
		discovered = append(discovered, parsed.Links...)
		discovered = append(discovered, parsed.Forms...)
		if c.cfg.EnableJavaScript {
			for _, js := range parsed.InlineJS {
				discovered = append(discovered, ExtractJSRoutes(js)...)
			}
		}
	case c.cfg.EnableJavaScript && (looksLikeJS(resp.ContentType) || strings.HasSuffix(norm.Path, ".js")):
		discovered = append(discovered, ExtractJSRoutes(string(resp.Body))...)
	case c.cfg.EnableOpenAPI && looksLikeOpenAPIDoc(norm.Path, resp.ContentType):
		if doc, err := ParseOpenAPI(resp.Body); err == nil {
			discovered = append(discovered, candidatesFromOpenAPI(doc, cand.Source)...)
			if doc.Version != "" {
				result.APIVersion = doc.Version
			}
		}
	}
	// Every candidate discovered on this page is relative to it until
	// resolved — stamp Base here, once, rather than in every extractor
	// (phase7.md §12: "<a href=...>" is always page-relative).
	for i := range discovered {
		if discovered[i].Base == "" {
			discovered[i].Base = norm.URL
		}
	}

	return result, discovered, len(resp.RedirectChain), nil
}

// mergeObservedConfidence is the confidence assigned once an endpoint has
// actually been observed via a real HTTP response — an actual response is
// the strongest possible signal (phase7.md §41's own example: "Actual
// HTTP response: very high"), always at least as strong as whatever
// weaker signal (a JavaScript string, an HTML link) first suggested the
// candidate.
func mergeObservedConfidence(candidateConfidence float64) float64 {
	const observedFloor = 0.95
	if candidateConfidence > observedFloor {
		return candidateConfidence
	}
	return observedFloor
}

func (c *Crawler) errorResult(cand Candidate, norm domainendpoint.Normalized, err error) Result {
	truncated := false
	if apperr, ok := apperrors.As(err); ok && apperr.Category == apperrors.CategoryValidation &&
		strings.Contains(apperr.Error(), "exceeds maximum size") {
		truncated = true
	}
	identity := applyPathTemplate(norm)
	class, apiType, apiVersion := Classify(identity.Path, "")
	return Result{
		URL: identity.URL, Scheme: identity.Scheme, Host: identity.Host, Port: identity.Port,
		Path: identity.Path, QueryPattern: norm.QueryPattern, Method: "GET",
		Classification: class, APIType: apiType, APIVersion: apiVersion,
		Sources: []string{cand.Source}, Confidence: cand.Confidence,
		Documented: cand.Documented, Inferred: cand.Inferred,
		Truncated:  truncated,
		Error:      err.Error(),
		Parameters: append(cand.Parameters, parametersFromQueryPattern(norm.QueryPattern)...),
		Evidence:   map[string]string{},
		ObservedAt: time.Now().UTC(),
	}
}

func looksLikeJS(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}

func looksLikeOpenAPIDoc(path, contentType string) bool {
	class, _, _ := Classify(path, contentType)
	return class == ClassOpenAPI || class == ClassSwagger
}

// looksLikeHTMLBody is a small last-resort fallback for a response that
// omitted Content-Type entirely — checks only for a literal "<html"
// prefix (after trimming leading whitespace), never a heuristic that
// could misclassify arbitrary binary data.
func looksLikeHTMLBody(body []byte) bool {
	trimmed := strings.TrimSpace(string(body[:min(len(body), 512)]))
	return strings.HasPrefix(strings.ToLower(trimmed), "<!doctype html") || strings.HasPrefix(strings.ToLower(trimmed), "<html")
}

// candidatesFromOpenAPI converts every documented operation into a
// Documented candidate (phase7.md §19/§46/§47) — never fetched
// automatically here; if the crawl's own independent GET-only link
// traversal separately reaches the same (method, path), the accumulator
// merges the two into one Observed+Documented Result.
func candidatesFromOpenAPI(doc OpenAPIDocument, source string) []Candidate {
	out := make([]Candidate, 0, len(doc.Operations))
	for _, op := range doc.Operations {
		evidence := op.Method + " " + op.Path
		if op.OperationID != "" {
			evidence += " (operationId: " + op.OperationID + ")"
		}
		out = append(out, Candidate{
			URL: op.Path, Method: op.Method, Source: source, Confidence: 0.85,
			Documented: true, Evidence: evidence, Parameters: op.ParameterNames,
		})
	}
	return out
}
