package network

import "fmt"

// Port-based service classification tables. This is deliberately the
// *only* signal used for Service (phase4.md §21: "classification should
// be conservative... a port number alone should not be treated as
// definitive proof") — no protocol payload is ever sent to an
// unclassified/unknown service to probe further (phase4.md §22). The one
// exception is the optional, bounded TLS handshake attempted for ports
// already classified HTTPS/TLS_SERVICE — see scanner.go's
// probeTLS — which sends nothing beyond the TLS handshake itself (no
// application data) and only ever upgrades an existing classification
// with corroborating evidence, never invents one from nothing.
var (
	sshPorts      = map[int]bool{22: true}
	ftpPorts      = map[int]bool{21: true}
	smtpPorts     = map[int]bool{25: true, 587: true}
	dnsPorts      = map[int]bool{53: true}
	httpPorts     = map[int]bool{80: true, 3000: true, 5000: true, 8000: true, 8008: true, 8080: true, 8081: true, 8088: true, 8888: true, 9000: true, 11434: true}
	httpsPorts    = map[int]bool{443: true, 8443: true}
	databasePorts = map[int]bool{3306: true, 5432: true, 6379: true, 27017: true, 1433: true, 1521: true}
	tlsPorts      = map[int]bool{993: true, 995: true} // IMAPS/POP3S — TLS-wrapped, not HTTP
	otherPorts    = map[int]bool{23: true, 3389: true, 5900: true, 9090: true, 9200: true, 9300: true, 11211: true, 50000: true}
)

// classifyPort returns the conservative, port-based Service category for
// port. It is never "proof" — see the package doc comment.
func classifyPort(port int) Service {
	switch {
	case sshPorts[port]:
		return ServiceSSH
	case ftpPorts[port]:
		return ServiceFTP
	case smtpPorts[port]:
		return ServiceSMTP
	case dnsPorts[port]:
		return ServiceDNS
	case httpsPorts[port]:
		return ServiceHTTPS
	case httpPorts[port]:
		return ServiceHTTP
	case databasePorts[port]:
		return ServiceDatabase
	case tlsPorts[port]:
		return ServiceTLS
	case otherPorts[port]:
		return ServiceOther
	default:
		return ServiceUnknown
	}
}

// classificationIndicator returns a human-readable explanation for a
// classifyPort result, for PortResult.Indicators.
func classificationIndicator(port int, service Service) string {
	if service == ServiceUnknown {
		return ""
	}
	return fmt.Sprintf("port %d is conventionally associated with %s (heuristic only, not confirmed)", port, service)
}

// httpCandidate reports whether port should be flagged HTTPCandidate —
// "worth a Phase 3 HTTP discovery pass", never a confirmed HTTP service
// (phase4.md §23).
func httpCandidate(port int, configuredPorts []int) bool {
	for _, p := range configuredPorts {
		if p == port {
			return true
		}
	}
	return false
}

// aiServiceCandidate reports whether port should be flagged
// AIServiceCandidate, and why. A true result means only "worth further
// HTTP/fingerprinting analysis" — never "confirmed AI service"
// (phase4.md §24).
func aiServiceCandidate(port int, configuredPorts []int) (bool, string) {
	for _, p := range configuredPorts {
		if p == port {
			return true, "configured_ai_port"
		}
	}
	return false, ""
}
