package httpclient

import (
	"fmt"
	"net"
	"syscall"
)

// blockedDialNetworks are address ranges this client refuses to connect to
// regardless of what hostname/redirect chain led there. They are all
// link-local-scoped ranges that are never a legitimate public or
// authorized-internal-pentest recon target — they exist to serve the
// *local host's own* network stack, not remote systems — but are exactly
// what a cloud metadata SSRF (phase15.md §49/§50) targets:
//
//   - 169.254.0.0/16 (IPv4 link-local) — this is where AWS/GCP/Azure/
//     OpenStack/Alibaba/DigitalOcean all serve their instance-metadata
//     endpoint (169.254.169.254), reachable only from the host it
//     describes. A "target" that resolves or redirects here (via DNS
//     rebinding, an open redirect, or attacker-controlled DNS) would hand
//     an attacker the operator's own cloud credentials.
//   - fe80::/10 (IPv6 link-local), and fd00:ec2::254 specifically (AWS
//     IMDSv2's IPv6 address — a unique-local address, not link-local, so
//     it needs its own explicit entry rather than falling under fe80::/10).
//
// Deliberately NOT blocked here: loopback (127.0.0.0/8, ::1) and RFC1918/
// ULA private ranges. Loopback is normal for local development/tests
// (see internal/httpclient/ssrf_test.go), and this platform's own
// SECURITY.md documents internal-network authorized penetration testing as
// a supported use case — an operator scanning their own internal
// 10.0.0.0/8 estate is not an SSRF victim, they're doing their job. Only
// the metadata-serving link-local range is blocked unconditionally,
// because there is no legitimate recon target that is a link-local
// address.
var blockedDialNetworks = mustParseCIDRs(
	"169.254.0.0/16",    // IPv4 link-local — cloud metadata services live here
	"fe80::/10",         // IPv6 link-local
	"fd00:ec2::254/128", // AWS IMDSv2's IPv6 address — a ULA, not link-local,
	// so it needs its own explicit entry rather than falling under fe80::/10.
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("httpclient: invalid built-in CIDR " + c + ": " + err.Error())
		}
		nets = append(nets, n)
	}
	return nets
}

// errBlockedAddress is returned (wrapped) when a dial target falls inside
// blockedDialNetworks.
type errBlockedAddress struct {
	addr string
}

func (e *errBlockedAddress) Error() string {
	return fmt.Sprintf("httpclient: refusing to connect to link-local/metadata address %s", e.addr)
}

// dialControl is installed as net.Dialer.Control. Go's dialer calls Control
// with the specific resolved address it is about to connect() to — after
// DNS resolution but immediately before the connect syscall — so checking
// here (rather than checking the hostname before resolution) is immune to
// DNS-rebinding: whatever name resolution or redirect chain produced this
// address, the address actually being dialed is what gets checked.
func dialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP literal at Control time would be unusual (the dialer
		// resolves before calling Control), but fail closed rather than
		// silently allow an unrecognized address form.
		return fmt.Errorf("httpclient: could not parse dial address %q", address)
	}
	for _, blocked := range blockedDialNetworks {
		if blocked.Contains(ip) {
			return &errBlockedAddress{addr: ip.String()}
		}
	}
	return nil
}
