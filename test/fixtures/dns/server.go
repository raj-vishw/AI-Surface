// Package dnsfixture provides a deterministic, fully local authoritative-
// style DNS server (UDP) used by internal/discovery/dns's tests (unit and
// integration) and the Phase 5 manual verification walkthrough. It never
// talks to a real upstream resolver or the public Internet — phase5.md
// §57 explicitly requires tests not depend on public DNS.
package dnsfixture

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Server is the fixture DNS service.
type Server struct {
	udpServer *dns.Server
	pc        net.PacketConn

	mu        sync.RWMutex
	zone      map[string][]dns.RR // key: lower(qname)+"|"+qtype string, e.g. "api.example.test.|A"
	names     map[string]bool     // every name with at least one record, for NXDOMAIN vs NODATA
	wildcards map[string][]dns.RR // key: lower(wildcard base domain, with trailing dot), e.g. "wildcard.example.test."
	ready     chan struct{}
}

// New starts a Server on an OS-assigned ephemeral UDP port, pre-loaded
// with the deterministic zone phase5.md §57 describes, and returns
// immediately — the caller must Close it.
func New() (*Server, error) {
	return newOn("127.0.0.1:0")
}

// NewOnPort starts a Server on a specific, caller-chosen port (used by the
// standalone fixture binary — cmd/dnsserver — for manual testing, where a
// predictable port is needed to pass to --resolver-address-equivalent
// configuration).
func NewOnPort(port int) (*Server, error) {
	return newOn(fmt.Sprintf("127.0.0.1:%d", port))
}

func newOn(addr string) (*Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	s := &Server{
		pc:        pc,
		zone:      make(map[string][]dns.RR),
		names:     make(map[string]bool),
		wildcards: make(map[string][]dns.RR),
		ready:     make(chan struct{}),
	}
	s.loadDefaultZone()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.udpServer = &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(s.ready) }}

	go func() { _ = s.udpServer.ActivateAndServe() }()
	<-s.ready

	return s, nil
}

// Addr returns the fixture's "host:port" listen address, suitable for
// internal/discovery/dns.NewExplicitResolver.
func (s *Server) Addr() string { return s.pc.LocalAddr().String() }

// Close shuts the fixture down. Safe to call once per Server.
func (s *Server) Close() error {
	return s.udpServer.Shutdown()
}

// SetRecords replaces every record for (name, type) — used to simulate a
// DNS change between scans (phase5.md §37/§62/§75). name is zone-file
// syntax accepted by dns.NewRR, e.g.:
//
//	s.SetRecords("api.example.test.", dns.TypeA, "api.example.test. 300 IN A 192.0.2.20")
func (s *Server) SetRecords(name string, qtype uint16, zoneLines ...string) error {
	rrs := make([]dns.RR, 0, len(zoneLines))
	for _, line := range zoneLines {
		rr, err := dns.NewRR(line)
		if err != nil {
			return fmt.Errorf("parsing zone line %q: %w", line, err)
		}
		rrs = append(rrs, rr)
	}

	key := recordKey(name, qtype)
	s.mu.Lock()
	s.zone[key] = rrs
	s.names[dns.Fqdn(strings.ToLower(name))] = true
	s.mu.Unlock()
	return nil
}

// SetWildcard registers a wildcard answer for every name under baseDomain
// that has no more specific explicit record (phase5.md §58) —
// "*.baseDomain" in conventional zone-file notation.
func (s *Server) SetWildcard(baseDomain string, zoneLines ...string) error {
	rrs := make([]dns.RR, 0, len(zoneLines))
	for _, line := range zoneLines {
		rr, err := dns.NewRR(line)
		if err != nil {
			return fmt.Errorf("parsing zone line %q: %w", line, err)
		}
		rrs = append(rrs, rr)
	}
	s.mu.Lock()
	s.wildcards[dns.Fqdn(strings.ToLower(baseDomain))] = rrs
	s.mu.Unlock()
	return nil
}

func recordKey(name string, qtype uint16) string {
	return dns.Fqdn(strings.ToLower(name)) + "|" + dns.TypeToString[qtype]
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) != 1 {
		msg.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(msg)
		return
	}
	q := r.Question[0]
	qname := strings.ToLower(q.Name)

	s.mu.RLock()
	rrs, exact := s.zone[qname+"|"+dns.TypeToString[q.Qtype]]
	nameKnown := s.names[qname]
	var wildcardRRs []dns.RR
	var wildcardMatched bool
	if !exact {
		for base, wrrs := range s.wildcards {
			if qname != base && strings.HasSuffix(qname, "."+base) {
				wildcardRRs = wrrs
				wildcardMatched = true
				break
			}
		}
	}
	s.mu.RUnlock()

	switch {
	case exact:
		msg.Answer = rrs
		msg.Rcode = dns.RcodeSuccess
	case wildcardMatched:
		// Only answer with the wildcard's records if they match the
		// requested type — otherwise it's NODATA for this type, same as
		// an explicit name would be.
		for _, rr := range wildcardRRs {
			if rr.Header().Rrtype == q.Qtype {
				msg.Answer = append(msg.Answer, rr)
			}
		}
		msg.Rcode = dns.RcodeSuccess
	case nameKnown:
		msg.Rcode = dns.RcodeSuccess // NOERROR, no records of this type: NODATA
	default:
		msg.Rcode = dns.RcodeNameError // NXDOMAIN
	}

	_ = w.WriteMsg(msg)
}

// loadDefaultZone populates the deterministic fixture data phase5.md §57
// requires: example.test, api.example.test, dev.example.test,
// staging.example.test, backend.example.test, wildcard.example.test (with
// a wildcard), and missing.example.test deliberately left absent (NXDOMAIN).
func (s *Server) loadDefaultZone() {
	must := func(name string, qtype uint16, lines ...string) {
		if err := s.SetRecords(name, qtype, lines...); err != nil {
			panic(err) // fixture data is static and known-valid; a failure here is a programming error
		}
	}

	must("example.test.", dns.TypeA, "example.test. 300 IN A 192.0.2.10")
	must("example.test.", dns.TypeAAAA, "example.test. 300 IN AAAA 2001:db8::10")
	must("example.test.", dns.TypeMX, "example.test. 300 IN MX 10 mail.example.test.")
	must("example.test.", dns.TypeNS, "example.test. 300 IN NS ns1.example.test.", "example.test. 300 IN NS ns2.example.test.")
	must("example.test.", dns.TypeTXT, `example.test. 300 IN TXT "v=spf1 -all"`)
	must("example.test.", dns.TypeSOA, "example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 2024010100 7200 3600 1209600 300")
	must("example.test.", dns.TypeCAA, `example.test. 300 IN CAA 0 issue "letsencrypt.org"`)

	must("api.example.test.", dns.TypeA, "api.example.test. 300 IN A 192.0.2.11")
	must("api.example.test.", dns.TypeAAAA, "api.example.test. 300 IN AAAA 2001:db8::11")

	// Reverse (PTR) records for the addresses above (phase5.md §19).
	must("10.2.0.192.in-addr.arpa.", dns.TypePTR, "10.2.0.192.in-addr.arpa. 300 IN PTR example.test.")
	must("11.2.0.192.in-addr.arpa.", dns.TypePTR, "11.2.0.192.in-addr.arpa. 300 IN PTR api.example.test.")

	must("dev.example.test.", dns.TypeA, "dev.example.test. 300 IN A 192.0.2.12")

	must("staging.example.test.", dns.TypeA, "staging.example.test. 300 IN A 192.0.2.13")

	must("backend.example.test.", dns.TypeA, "backend.example.test. 300 IN A 192.0.2.14")

	// A CNAME relationship: an explicitly-named host pointing at
	// "backend.example.test" (phase5.md §13/§34).
	must("service.example.test.", dns.TypeCNAME, "service.example.test. 300 IN CNAME backend.example.test.")

	// Base domain for the wildcard zone: has its own explicit records
	// (so the domain itself isn't NXDOMAIN) plus a wildcard for anything
	// underneath.
	must("wildcard.example.test.", dns.TypeA, "wildcard.example.test. 300 IN A 192.0.2.99")
	if err := s.SetWildcard("wildcard.example.test.", "wildcard.example.test. 300 IN A 203.0.113.50"); err != nil {
		panic(err)
	}
	// A distinct, explicitly-configured record under the wildcard domain
	// — must still be recognized as a real, independent record despite
	// the wildcard (phase5.md §58).
	must("api.wildcard.example.test.", dns.TypeA, "api.wildcard.example.test. 300 IN A 192.0.2.77")

	// missing.example.test is deliberately never added — querying it
	// must produce NXDOMAIN.
}
