package endpoint

import (
	"strings"

	"golang.org/x/net/html"
)

// HTMLParseResult is everything statically extracted from one HTML
// document (phase7.md §12/§13) — links, forms, and script/stylesheet
// references. JavaScript is never executed; this is a pure static parse
// of the already-fetched, bounded response body.
type HTMLParseResult struct {
	Links    []Candidate // a/area href, iframe src, link href (stylesheets and other resource links)
	Scripts  []string    // script src — fed into javascript.go if fetched separately, or analyzed inline
	InlineJS []string    // the text content of <script> blocks with no src — analyzed the same way as a fetched .js file
	Forms    []Candidate
}

// ParseHTML statically parses an HTML document (never executing any
// script) and extracts every link, form, and script reference. Every
// returned Candidate's URL is still raw (relative or absolute, as found
// in the markup) — normalization and scope validation happen afterward.
func ParseHTML(body []byte) HTMLParseResult {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return HTMLParseResult{}
	}

	var result HTMLParseResult
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a", "area":
				if href := attr(n, "href"); href != "" {
					result.Links = append(result.Links, Candidate{
						URL: href, Method: "GET", Source: "html_link", Confidence: 0.7,
						Evidence: sanitizedTag(n, "href", href),
					})
				}
			case "iframe":
				if src := attr(n, "src"); src != "" {
					result.Links = append(result.Links, Candidate{
						URL: src, Method: "GET", Source: "html_link", Confidence: 0.6,
						Evidence: sanitizedTag(n, "src", src),
					})
				}
			case "link":
				if href := attr(n, "href"); href != "" {
					result.Links = append(result.Links, Candidate{
						URL: href, Method: "GET", Source: "html_link", Confidence: 0.4,
						Evidence: sanitizedTag(n, "href", href),
					})
				}
			case "script":
				if src := attr(n, "src"); src != "" {
					result.Scripts = append(result.Scripts, src)
					result.Links = append(result.Links, Candidate{
						URL: src, Method: "GET", Source: "html_link", Confidence: 0.5,
						Evidence: sanitizedTag(n, "src", src),
					})
				} else if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					result.InlineJS = append(result.InlineJS, n.FirstChild.Data)
				}
			case "form":
				result.Forms = append(result.Forms, parseForm(n))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return result
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

// parseForm builds a Candidate from a <form> element: method (default
// GET per HTML semantics), action, and field names — never field values
// (phase7.md §13: "the system must NOT submit credentials... For
// password fields: field = password must be recorded as metadata only").
func parseForm(form *html.Node) Candidate {
	method := strings.ToUpper(attr(form, "method"))
	if method == "" {
		method = "GET"
	}
	action := attr(form, "action")

	var fields []Parameter
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea") {
			if name := attr(n, "name"); name != "" {
				fields = append(fields, Parameter{Name: name, Location: "form"})
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)

	fieldNames := make([]string, len(fields))
	for i, f := range fields {
		fieldNames[i] = f.Name
	}

	return Candidate{
		URL: action, Method: method, Source: "html_form", Confidence: 0.7,
		Evidence:   method + " " + action + " (fields: " + strings.Join(fieldNames, ", ") + ")",
		Parameters: fields,
	}
}

// sanitizedTag renders a short, safe evidence snippet for a discovered
// link — the tag name and the one attribute that mattered, never the
// element's full content/children (phase7.md §42: "do not persist
// complete pages unnecessarily").
func sanitizedTag(n *html.Node, attrName, value string) string {
	return "<" + n.Data + " " + attrName + "=\"" + value + "\">"
}
