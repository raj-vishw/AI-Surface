package dns

import "github.com/miekg/dns"

// ResolutionState is the outcome of resolving one DNS name (or PTR
// lookup). Distinguishing these precisely matters for wildcard detection
// and enumeration accuracy (phase5.md §26/§27) — NXDOMAIN ("this name
// does not exist") is never collapsed together with NO_ANSWER ("this name
// exists but has no record of the requested type"), SERVFAIL, or a
// transport timeout into one generic "not found".
type ResolutionState string

// Recognized resolution states.
const (
	// StateResolved means the query completed and returned at least one
	// answer of the requested type.
	StateResolved ResolutionState = "RESOLVED"
	// StateNXDOMAIN means the server authoritatively reported the name
	// does not exist (RCODE NXDOMAIN) — a real "not found", never
	// conflated with NoAnswer.
	StateNXDOMAIN ResolutionState = "NXDOMAIN"
	// StateNoAnswer means the query completed successfully (RCODE NOERROR)
	// but returned no records of the requested type — the name exists,
	// just not with this record type (classic "NODATA").
	StateNoAnswer ResolutionState = "NO_ANSWER"
	// StateTimeout means the query's deadline (or the scan's context) was
	// exceeded before a response arrived.
	StateTimeout ResolutionState = "TIMEOUT"
	// StateError means anything else — SERVFAIL, REFUSED, a malformed
	// response, connection failure, or any other transport/protocol
	// failure not covered above.
	StateError ResolutionState = "ERROR"
)

// classify turns a completed LookupResult (rcode + records) into a
// ResolutionState. Call this only when the query itself succeeded at the
// transport level — see classifyTransportError for the timeout/error path
// when it didn't.
func classify(result LookupResult) ResolutionState {
	switch result.Rcode {
	case dns.RcodeNameError: // NXDOMAIN
		return StateNXDOMAIN
	case dns.RcodeSuccess:
		if len(result.Records) > 0 {
			return StateResolved
		}
		return StateNoAnswer
	default: // SERVFAIL, REFUSED, NOTIMP, ...
		return StateError
	}
}
