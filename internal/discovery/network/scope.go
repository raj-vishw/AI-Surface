package network

import (
	"fmt"
	"net/netip"

	domaintarget "ai-surface-platform/internal/domain/target"
)

// ScopeChecker determines whether an expanded host is within an
// authorized network target's scope.
//
// This is deliberately a different check than HTTP discovery's hostname/
// subdomain-based internal/discovery/http.ScopeValidator — reusing that
// type here would be semantically wrong, not just architecturally
// convenient: an IP address has no "subdomain" relationship to another IP,
// and a CIDR block (e.g. "192.168.1.0/30") doesn't parse as a hostname at
// all. Network scope is address-membership based instead: a HOST/IP
// target's scope is exactly that one value; a CIDR target's scope is
// every address the CIDR itself contains. It is still the same
// authorization/scope *principle* Phase 3 established — approved
// membership, checked before every connection, never assumed — just
// expressed correctly for address targets (phase4.md §3/§13).
type ScopeChecker struct {
	targetType domaintarget.Type
	hostValue  string
	cidr       netip.Prefix
}

// NewScopeChecker builds a ScopeChecker for a HOST/IP/CIDR target.
func NewScopeChecker(targetType domaintarget.Type, value string) (*ScopeChecker, error) {
	switch targetType {
	case domaintarget.TypeHost, domaintarget.TypeIP:
		return &ScopeChecker{targetType: targetType, hostValue: value}, nil
	case domaintarget.TypeCIDR:
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		return &ScopeChecker{targetType: targetType, cidr: prefix.Masked()}, nil
	default:
		return nil, fmt.Errorf("target type %s is not supported by network discovery (only HOST, IP, CIDR)", targetType)
	}
}

// Allowed reports whether host is within scope: for a HOST/IP target, an
// exact match; for a CIDR target, address membership in the block.
func (c *ScopeChecker) Allowed(host string) bool {
	if c == nil {
		return false
	}
	switch c.targetType {
	case domaintarget.TypeHost, domaintarget.TypeIP:
		return host == c.hostValue
	case domaintarget.TypeCIDR:
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return false
		}
		return c.cidr.Contains(addr)
	default:
		return false
	}
}
