package endpoint

import "testing"

const testRobots = `User-agent: *
Disallow: /admin
Disallow: /private
Allow: /public
Allow: /admin
Sitemap: https://example.test/sitemap.xml
Sitemap: https://example.test/sitemap-news.xml
`

func TestParseRobots_Sitemaps(t *testing.T) {
	result := ParseRobots([]byte(testRobots))
	if len(result.Sitemaps) != 2 {
		t.Fatalf("Sitemaps = %v, want 2 entries", result.Sitemaps)
	}
	if result.Sitemaps[0] != "https://example.test/sitemap.xml" {
		t.Errorf("Sitemaps[0] = %q", result.Sitemaps[0])
	}
}

func TestParseRobots_DisallowIsJustACandidate(t *testing.T) {
	// phase7.md §23/§74: Disallow is not an authorization boundary — it
	// must appear as an ordinary candidate path, identically to Allow.
	result := ParseRobots([]byte(testRobots))
	want := map[string]bool{"/admin": true, "/private": true, "/public": true}
	got := map[string]bool{}
	for _, p := range result.Paths {
		got[p] = true
	}
	for p := range want {
		if !got[p] {
			t.Errorf("expected path %q among candidates, got %v", p, result.Paths)
		}
	}
}

func TestParseRobots_DuplicatesCollapsed(t *testing.T) {
	// /admin appears in both a Disallow and an Allow line — must appear
	// only once in Paths.
	result := ParseRobots([]byte(testRobots))
	count := 0
	for _, p := range result.Paths {
		if p == "/admin" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("/admin appeared %d times, want 1", count)
	}
}

func TestParseRobots_Empty(t *testing.T) {
	result := ParseRobots([]byte(""))
	if len(result.Paths) != 0 || len(result.Sitemaps) != 0 {
		t.Errorf("expected empty result, got %+v", result)
	}
}

func TestParseRobots_CommentsAndBlankLinesIgnored(t *testing.T) {
	body := "# a comment\n\nUser-agent: *\n\n# another comment\nDisallow: /x\n"
	result := ParseRobots([]byte(body))
	if len(result.Paths) != 1 || result.Paths[0] != "/x" {
		t.Errorf("Paths = %v, want [/x]", result.Paths)
	}
}
