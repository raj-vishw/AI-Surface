package endpoint

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

type sitemapURLSet struct {
	URLs []sitemapEntry `xml:"url"`
}

type sitemapEntry struct {
	Loc string `xml:"loc"`
}

type sitemapIndex struct {
	Sitemaps []sitemapIndexItem `xml:"sitemap"`
}

type sitemapIndexItem struct {
	Loc string `xml:"loc"`
}

// SitemapParseResult is the outcome of parsing one sitemap.xml document —
// either a leaf sitemap (URLs) or a sitemap index (ChildSitemaps), never
// both (phase7.md §22).
type SitemapParseResult struct {
	URLs          []string
	ChildSitemaps []string
}

// ParseSitemap parses body as either a <urlset> (leaf sitemap, phase7.md
// §22's "parse <loc>") or a <sitemapindex> (a sitemap of sitemaps),
// determined by inspecting the document's actual root element first — an
// empty-but-valid <urlset/> is zero URLs, never a parse error. It does
// not itself bound recursion or URL counts — see crawler.go's
// fetchSitemap, which enforces MaxSitemaps/MaxSitemapURLs and cycle
// detection across the whole sitemap tree (phase7.md §22's "bounded
// recursion... do not follow unlimited sitemap chains").
func ParseSitemap(body []byte) (SitemapParseResult, error) {
	root, err := rootElementName(body)
	if err != nil {
		return SitemapParseResult{}, fmt.Errorf("parsing sitemap: %w", err)
	}

	switch root {
	case "urlset":
		var urlset sitemapURLSet
		if err := xml.Unmarshal(body, &urlset); err != nil {
			return SitemapParseResult{}, fmt.Errorf("parsing sitemap urlset: %w", err)
		}
		urls := make([]string, 0, len(urlset.URLs))
		for _, u := range urlset.URLs {
			if u.Loc != "" {
				urls = append(urls, u.Loc)
			}
		}
		return SitemapParseResult{URLs: urls}, nil
	case "sitemapindex":
		var index sitemapIndex
		if err := xml.Unmarshal(body, &index); err != nil {
			return SitemapParseResult{}, fmt.Errorf("parsing sitemap index: %w", err)
		}
		children := make([]string, 0, len(index.Sitemaps))
		for _, s := range index.Sitemaps {
			if s.Loc != "" {
				children = append(children, s.Loc)
			}
		}
		return SitemapParseResult{ChildSitemaps: children}, nil
	default:
		return SitemapParseResult{}, fmt.Errorf("unrecognized sitemap root element %q", root)
	}
}

// rootElementName returns the local name of body's outermost XML
// element, without unmarshalling into any particular struct — used to
// decide which of ParseSitemap's two shapes applies.
func rootElementName(body []byte) (string, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start.Name.Local, nil
		}
	}
}
