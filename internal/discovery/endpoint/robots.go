package endpoint

import "strings"

// RobotsResult is the outcome of parsing a robots.txt document.
type RobotsResult struct {
	// Sitemaps are every "Sitemap:" directive value found — candidate
	// sitemap URLs, still subject to scope validation before any are
	// fetched (phase7.md §22/§23).
	Sitemaps []string
	// Paths are every distinct "Allow:"/"Disallow:" directive value —
	// candidate endpoint paths (phase7.md §23). robots.txt is explicitly
	// NOT an authorization boundary (phase7.md §23, in capitals in the
	// spec): a Disallow entry is recorded as an ordinary candidate the
	// same as an Allow entry, never treated as "forbidden to scan" —
	// scope/authorization remain the only real boundaries, enforced
	// identically for every candidate regardless of which directive
	// produced it.
	Paths []string
}

// ParseRobots parses a robots.txt document's raw bytes. It never treats a
// Disallow directive specially — see RobotsResult's doc comment.
func ParseRobots(body []byte) RobotsResult {
	var result RobotsResult
	seen := make(map[string]bool)

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		directive := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		if value == "" {
			continue
		}

		switch directive {
		case "sitemap":
			result.Sitemaps = append(result.Sitemaps, value)
		case "allow", "disallow":
			if !seen[value] {
				seen[value] = true
				result.Paths = append(result.Paths, value)
			}
		}
	}
	return result
}
