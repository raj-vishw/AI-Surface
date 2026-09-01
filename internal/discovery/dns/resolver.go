package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// LookupResult is one DNS query's protocol-level outcome. Rcode captures
// what the server said (NOERROR, NXDOMAIN, SERVFAIL, ...) — a completed
// exchange, never an error on its own; a transport failure (timeout,
// connection refused, network unreachable) is reported through Lookup's
// error return instead. Classifying the two together as one "not found"
// bucket is exactly what phase5.md §26/§27 forbids.
type LookupResult struct {
	Records []Record
	Rcode   int
}

// Resolver looks up DNS records for a name, or PTR records for an IP. The
// scanner depends only on this interface — never on a concrete DNS
// implementation — so it is usable from the CLI, a future REST API, or a
// future worker without coupling to any of them (phase5.md §6).
type Resolver interface {
	Lookup(ctx context.Context, name string, recordType RecordType) (LookupResult, error)
	LookupPTR(ctx context.Context, ip string) (LookupResult, error)
}

// resolver is the concrete Resolver: SystemResolver and ExplicitResolver
// (below) are both just constructors for it, differing only in which
// servers they query. There is exactly one query implementation —
// "system" vs "explicit" is a difference in server list, not in
// mechanism (phase5.md §9).
type resolver struct {
	servers []string // "host:port", queried in order until one answers
	client  *dns.Client
}

// NewExplicitResolver builds a Resolver that queries exactly the given
// "host:port" servers (phase5.md §8) — no public resolver is required;
// tests use a local fixture exclusively.
func NewExplicitResolver(servers []string, timeout time.Duration) (Resolver, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("at least one DNS server is required")
	}
	normalized := make([]string, len(servers))
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			return nil, fmt.Errorf("invalid resolver address %q: %w", s, err)
		}
		normalized[i] = s
	}
	return &resolver{servers: normalized, client: &dns.Client{Timeout: timeout}}, nil
}

// NewSystemResolver builds a Resolver from the operating system's
// configured nameservers (/etc/resolv.conf on Unix) — the "use the OS
// resolver" option (phase5.md §8/§9).
func NewSystemResolver(timeout time.Duration) (Resolver, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("reading system resolver configuration: %w", err)
	}
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("no nameservers configured in /etc/resolv.conf")
	}
	servers := make([]string, len(cfg.Servers))
	for i, s := range cfg.Servers {
		servers[i] = net.JoinHostPort(s, cfg.Port)
	}
	return NewExplicitResolver(servers, timeout)
}

// Lookup implements Resolver.
func (r *resolver) Lookup(ctx context.Context, name string, recordType RecordType) (LookupResult, error) {
	qtype, ok := recordTypeToQtype[recordType]
	if !ok {
		return LookupResult{}, fmt.Errorf("unsupported record type %q", recordType)
	}
	return r.query(ctx, dns.Fqdn(name), qtype, name, recordType)
}

// LookupPTR implements Resolver — a reverse lookup for an IP address
// already within scope (phase5.md §19), never unrestricted reverse-DNS
// scanning; the scanner is what enforces that this is only ever called
// for an already-discovered, in-scope address (see scanner.go).
func (r *resolver) LookupPTR(ctx context.Context, ip string) (LookupResult, error) {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return LookupResult{}, fmt.Errorf("invalid IP address %q: %w", ip, err)
	}
	return r.query(ctx, arpa, dns.TypePTR, ip, TypePTR)
}

func (r *resolver) query(ctx context.Context, qname string, qtype uint16, originalName string, recordType RecordType) (LookupResult, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.RecursionDesired = true

	var lastErr error
	for _, server := range r.servers {
		resp, _, err := r.client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return LookupResult{}, ctx.Err()
			}
			continue // try the next configured server
		}
		records, parseErr := parseAnswers(resp.Answer, originalName, recordType)
		if parseErr != nil {
			return LookupResult{}, parseErr
		}
		return LookupResult{Records: records, Rcode: resp.Rcode}, nil
	}
	return LookupResult{}, fmt.Errorf("all configured resolvers failed: %w", lastErr)
}

var recordTypeToQtype = map[RecordType]uint16{
	TypeA: dns.TypeA, TypeAAAA: dns.TypeAAAA, TypeCNAME: dns.TypeCNAME,
	TypeMX: dns.TypeMX, TypeNS: dns.TypeNS, TypeTXT: dns.TypeTXT,
	TypeSOA: dns.TypeSOA, TypeCAA: dns.TypeCAA, TypePTR: dns.TypePTR,
}

// parseAnswers converts miekg/dns resource records into this package's
// normalized Record type. Record types outside the requested query type
// (e.g. a CNAME returned alongside an A query) are skipped — they belong
// to whatever query would have asked for them explicitly.
func parseAnswers(answers []dns.RR, name string, want RecordType) ([]Record, error) {
	var records []Record
	for _, rr := range answers {
		header := rr.Header()
		record := Record{Name: name, TTL: header.Ttl}

		switch v := rr.(type) {
		case *dns.A:
			if want != TypeA {
				continue
			}
			record.Type = TypeA
			record.Value = v.A.String()
		case *dns.AAAA:
			if want != TypeAAAA {
				continue
			}
			record.Type = TypeAAAA
			record.Value = v.AAAA.String()
		case *dns.CNAME:
			if want != TypeCNAME {
				continue
			}
			record.Type = TypeCNAME
			record.Value = normalizeOrRaw(v.Target)
		case *dns.MX:
			if want != TypeMX {
				continue
			}
			priority := int(v.Preference)
			record.Type = TypeMX
			record.Value = normalizeOrRaw(v.Mx)
			record.Priority = &priority
		case *dns.NS:
			if want != TypeNS {
				continue
			}
			record.Type = TypeNS
			record.Value = normalizeOrRaw(v.Ns)
		case *dns.TXT:
			if want != TypeTXT {
				continue
			}
			record.Type = TypeTXT
			record.Value = SanitizeTXTValue(joinTXT(v.Txt))
		case *dns.SOA:
			if want != TypeSOA {
				continue
			}
			record.Type = TypeSOA
			record.Value = normalizeOrRaw(v.Ns)
			record.SOA = &SOAData{
				PrimaryNS: normalizeOrRaw(v.Ns), Mailbox: normalizeOrRaw(v.Mbox),
				Serial: v.Serial, Refresh: v.Refresh, Retry: v.Retry,
				Expire: v.Expire, MinimumTTL: v.Minttl,
			}
		case *dns.CAA:
			if want != TypeCAA {
				continue
			}
			record.Type = TypeCAA
			record.Value = v.Value
			record.CAA = &CAAData{Flag: v.Flag, Tag: v.Tag, Value: v.Value}
		case *dns.PTR:
			if want != TypePTR {
				continue
			}
			record.Type = TypePTR
			record.Value = normalizeOrRaw(v.Ptr)
		default:
			continue
		}

		records = append(records, record)
	}
	return records, nil
}

// normalizeOrRaw normalizes a name from a DNS response, falling back to
// the raw (lowercased, dot-trimmed) value if it somehow fails validation
// (a permissive fallback for parsing responses, unlike NormalizeName's
// strict validation of user/config-supplied input).
func normalizeOrRaw(name string) string {
	if normalized, err := NormalizeName(name); err == nil {
		return normalized
	}
	return dns.Fqdn(name)
}

func joinTXT(chunks []string) string {
	out := ""
	for i, c := range chunks {
		if i > 0 {
			out += " "
		}
		out += c
	}
	return out
}

// classifyTransportError distinguishes a timeout from any other transport
// failure — the same discipline internal/discovery/network.
// classifyDialError applies (phase5.md §26/§27/§60).
func classifyTransportError(err error) ResolutionState {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return StateTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	return StateError
}
