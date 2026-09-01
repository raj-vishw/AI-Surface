// Package network implements the TCP connect discovery engine: port list/
// range parsing, host/CIDR target expansion, scope-aware bounded-
// concurrency TCP connect scanning, and conservative service/AI-candidate
// classification. It never persists anything and never touches
// PostgreSQL — internal/discovery/service (Phase 3's orchestration layer,
// extended rather than duplicated for Phase 4) does that.
package network

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// MinPort and MaxPort bound a valid TCP port (phase4.md §9).
const (
	MinPort = 1
	MaxPort = 65535
)

// ParsePorts parses a port specification into a deterministic, deduplicated,
// sorted list of ports. Accepted syntax:
//
//	"80"                     single port
//	"80,443,8080"            comma-separated list
//	"8000-8010"               inclusive range
//	"80,443,8000-8010,11434" mixed
//
// Malformed input is rejected outright — ParsePorts never silently
// corrects it (phase4.md §9): empty entries, non-numeric values, ports
// outside [1, 65535], and reversed ranges (start > end) all return a
// descriptive error naming the offending token.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("port specification must not be empty")
	}

	seen := make(map[int]bool)
	var ports []int

	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("invalid port specification: empty value between commas")
		}

		if strings.Contains(token, "-") {
			start, end, err := parseRange(token)
			if err != nil {
				return nil, err
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
			continue
		}

		port, err := parsePort(token)
		if err != nil {
			return nil, err
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}

	sort.Ints(ports)
	return ports, nil
}

func parsePort(token string) (int, error) {
	n, err := strconv.Atoi(token)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: not a number", token)
	}
	if n < MinPort || n > MaxPort {
		return 0, fmt.Errorf("invalid port %d: must be between %d and %d", n, MinPort, MaxPort)
	}
	return n, nil
}

func parseRange(token string) (start, end int, err error) {
	parts := strings.SplitN(token, "-", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return 0, 0, fmt.Errorf("invalid port range %q: expected <start>-<end>", token)
	}

	start, err = parsePort(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q: %w", token, err)
	}
	end, err = parsePort(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q: %w", token, err)
	}
	if start > end {
		return 0, 0, fmt.Errorf("invalid port range %q: start port must not exceed end port", token)
	}
	return start, end, nil
}
