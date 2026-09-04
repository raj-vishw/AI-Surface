package endpoint

import "testing"

const testSitemapURLSet = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.test/</loc></url>
  <url><loc>https://example.test/about</loc></url>
  <url><loc>https://example.test/about</loc></url>
</urlset>`

const testSitemapIndex = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.test/sitemap-1.xml</loc></sitemap>
  <sitemap><loc>https://example.test/sitemap-2.xml</loc></sitemap>
</sitemapindex>`

func TestParseSitemap_URLSet(t *testing.T) {
	result, err := ParseSitemap([]byte(testSitemapURLSet))
	if err != nil {
		t.Fatalf("ParseSitemap: %v", err)
	}
	if len(result.URLs) != 3 { // parser itself doesn't dedup — caller does
		t.Fatalf("URLs = %v, want 3 raw entries", result.URLs)
	}
	if len(result.ChildSitemaps) != 0 {
		t.Errorf("ChildSitemaps = %v, want none for a leaf urlset", result.ChildSitemaps)
	}
}

func TestParseSitemap_Index(t *testing.T) {
	result, err := ParseSitemap([]byte(testSitemapIndex))
	if err != nil {
		t.Fatalf("ParseSitemap: %v", err)
	}
	if len(result.ChildSitemaps) != 2 {
		t.Fatalf("ChildSitemaps = %v, want 2", result.ChildSitemaps)
	}
	if len(result.URLs) != 0 {
		t.Errorf("URLs = %v, want none for a sitemapindex", result.URLs)
	}
}

func TestParseSitemap_EmptyURLSetIsNotAnError(t *testing.T) {
	result, err := ParseSitemap([]byte(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>`))
	if err != nil {
		t.Fatalf("ParseSitemap(empty urlset): %v", err)
	}
	if len(result.URLs) != 0 {
		t.Errorf("URLs = %v, want empty", result.URLs)
	}
}

func TestParseSitemap_Malformed(t *testing.T) {
	if _, err := ParseSitemap([]byte("not xml at all")); err == nil {
		t.Error("expected an error for malformed XML")
	}
}

func TestParseSitemap_UnrecognizedRoot(t *testing.T) {
	if _, err := ParseSitemap([]byte(`<rss><channel></channel></rss>`)); err == nil {
		t.Error("expected an error for an unrecognized root element")
	}
}
