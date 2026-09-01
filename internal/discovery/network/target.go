package network

import (
	"fmt"
	"net"
	"net/netip"

	domaintarget "ai-recon-platform/internal/domain/target"
)

// supportedTargetTypes are the target types network discovery accepts
// (phase4.md §10) — anything else (URL, REPOSITORY, CLOUD_ACCOUNT, ...) is
// rejected before any expansion or connection attempt. DOMAIN is
// deliberately excluded: resolving a domain to IPs is a DNS operation this
// phase does not perform (phase4.md §10 — "domain targets may be resolved
// only if the existing Target abstraction already provides a safe,
// explicit resolution mechanism," and it does not yet); scanning a domain
// target requires giving its IP/HOST explicitly.
var supportedTargetTypes = map[domaintarget.Type]bool{
	domaintarget.TypeHost: true,
	domaintarget.TypeIP:   true,
	domaintarget.TypeCIDR: true,
}

// SupportedTargetType reports whether typ can be expanded by ExpandTarget.
func SupportedTargetType(typ domaintarget.Type) bool {
	return supportedTargetTypes[typ]
}

// ExpandTarget deterministically expands a target's (type, value) into the
// concrete host addresses/names to scan.
//
//   - HOST / IP: value is used as-is — a single-element result.
//   - CIDR: every usable host address in the block, in ascending numeric
//     order. "Usable" follows the standard subnetting convention: for an
//     IPv4 block with room for 4 or more addresses (prefix length <= 30),
//     the network address and broadcast address are excluded (they don't
//     identify a scannable host); for /31 (point-to-point, RFC 3021) and
//     /32 (single host), every address is included since there is no
//     network/broadcast address to exclude. IPv6 has no broadcast concept,
//     so every address in the block is included regardless of prefix
//     length.
//
// maxHosts bounds CIDR expansion (phase4.md §11): exceeding it is an error
// — ExpandTarget never silently truncates the result.
func ExpandTarget(targetType domaintarget.Type, value string, maxHosts int) ([]string, error) {
	switch targetType {
	case domaintarget.TypeHost, domaintarget.TypeIP:
		return []string{value}, nil
	case domaintarget.TypeCIDR:
		return expandCIDR(value, maxHosts)
	default:
		return nil, fmt.Errorf("target type %s is not supported by network discovery (only HOST, IP, CIDR)", targetType)
	}
}

func expandCIDR(cidr string, maxHosts int) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	prefix = prefix.Masked()

	count, err := hostCount(prefix)
	if err != nil {
		return nil, err
	}
	if count > maxHosts {
		return nil, fmt.Errorf("network target exceeds configured host limit: %s expands to %d hosts, max_hosts is %d", cidr, count, maxHosts)
	}

	var hosts []string
	network := prefix.Addr()
	isIPv4 := network.Is4()
	excludeNetworkAndBroadcast := isIPv4 && prefix.Bits() <= 30

	for addr := network; prefix.Contains(addr); {
		isNetworkOrBroadcast := addr == network || addr == lastAddr(prefix)
		if !excludeNetworkAndBroadcast || !isNetworkOrBroadcast {
			hosts = append(hosts, addr.String())
		}
		next := addr.Next()
		if !next.IsValid() || next == addr {
			break
		}
		addr = next
	}

	return hosts, nil
}

// hostCount returns the total number of addresses prefix contains
// (including network/broadcast, before the usable-address exclusion),
// erroring rather than overflowing for very large IPv6 blocks — this
// project never needs to actually enumerate those; a small max_hosts
// rejects them long before enumeration would.
func hostCount(prefix netip.Prefix) (int, error) {
	bits := prefix.Addr().BitLen() - prefix.Bits()
	if bits > 32 {
		// Any block this large vastly exceeds any sane max_hosts; report a
		// value guaranteed to exceed the configured limit without
		// attempting to compute an exact (and here, un-representable as
		// an int) count.
		return int(^uint(0) >> 1), nil
	}
	return 1 << uint(bits), nil
}

// lastAddr returns the highest address in prefix (its broadcast address,
// for an IPv4 block) by OR-ing every host bit to 1.
func lastAddr(prefix netip.Prefix) netip.Addr {
	base := prefix.Addr()
	mask := net.CIDRMask(prefix.Bits(), base.BitLen())
	bytes := base.AsSlice()
	for i := range bytes {
		bytes[i] |= ^mask[i]
	}
	last, ok := netip.AddrFromSlice(bytes)
	if !ok {
		return base
	}
	if base.Is4() {
		last = last.Unmap()
	}
	return last
}
