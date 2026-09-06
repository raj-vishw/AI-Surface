package httpclient

import (
	"errors"
	"testing"
)

func TestDialControl_BlocksLinkLocalAndMetadata(t *testing.T) {
	cases := []string{
		"169.254.169.254:80", // AWS/GCP/Azure/OpenStack/DO instance metadata
		"169.254.0.1:443",
		"[fe80::1]:80",
		"[fd00:ec2::254]:80", // AWS IMDSv2 over IPv6
	}
	for _, addr := range cases {
		if err := dialControl("tcp", addr, nil); err == nil {
			t.Errorf("dialControl(%q): expected error, got nil", addr)
		} else {
			var blocked *errBlockedAddress
			if !errors.As(err, &blocked) {
				t.Errorf("dialControl(%q): expected *errBlockedAddress, got %T: %v", addr, err, err)
			}
		}
	}
}

func TestDialControl_AllowsLoopbackAndPrivateAndPublic(t *testing.T) {
	cases := []string{
		"127.0.0.1:80",      // loopback — used by local dev/tests
		"[::1]:80",          // loopback
		"10.0.0.5:443",      // RFC1918 — internal-pentest use case is supported
		"192.168.1.1:22",    // RFC1918
		"93.184.216.34:443", // public address (example.com)
	}
	for _, addr := range cases {
		if err := dialControl("tcp", addr, nil); err != nil {
			t.Errorf("dialControl(%q): expected nil, got %v", addr, err)
		}
	}
}

func TestDialControl_RejectsUnparseableAddress(t *testing.T) {
	if err := dialControl("tcp", "not-an-address:::", nil); err == nil {
		t.Error("dialControl with unparseable host: expected error, got nil")
	}
}
