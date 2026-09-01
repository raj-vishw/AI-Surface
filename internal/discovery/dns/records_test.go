package dns

import "testing"

func TestRecord_Identity(t *testing.T) {
	priority := 10
	tests := []struct {
		name string
		r    Record
		want string
	}{
		{
			name: "A record, no priority",
			r:    Record{Name: "example.test", Type: TypeA, Value: "192.0.2.10", TTL: 300},
			want: "example.test|A|192.0.2.10|",
		},
		{
			name: "MX record, with priority",
			r:    Record{Name: "example.test", Type: TypeMX, Value: "mail.example.test", Priority: &priority, TTL: 300},
			want: "example.test|MX|mail.example.test|10",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Identity(); got != tc.want {
				t.Errorf("Identity() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRecord_Identity_ExcludesTTL(t *testing.T) {
	r1 := Record{Name: "example.test", Type: TypeA, Value: "192.0.2.10", TTL: 300}
	r2 := Record{Name: "example.test", Type: TypeA, Value: "192.0.2.10", TTL: 60}
	if r1.Identity() != r2.Identity() {
		t.Errorf("Identity() differs across TTL values: %q vs %q — TTL must not affect record identity", r1.Identity(), r2.Identity())
	}
	if r1.Fingerprint() != r2.Fingerprint() {
		t.Errorf("Fingerprint() differs across TTL values — TTL fluctuation must not defeat evidence dedup")
	}
}

func TestRecord_Fingerprint_DeterministicAndDistinct(t *testing.T) {
	a := Record{Name: "example.test", Type: TypeA, Value: "192.0.2.10"}
	b := Record{Name: "example.test", Type: TypeA, Value: "192.0.2.11"}

	first, second := a.Fingerprint(), a.Fingerprint()
	if first != second {
		t.Errorf("Fingerprint() is not deterministic: %q vs %q", first, second)
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Errorf("Fingerprint() collided for distinct records")
	}
	if len(a.Fingerprint()) != 64 {
		t.Errorf("Fingerprint() length = %d, want 64 (SHA-256 hex)", len(a.Fingerprint()))
	}
}

func TestValidForwardType(t *testing.T) {
	for _, rt := range []RecordType{TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeNS, TypeTXT, TypeSOA, TypeCAA} {
		if !ValidForwardType(rt) {
			t.Errorf("ValidForwardType(%s) = false, want true", rt)
		}
	}
	if ValidForwardType(TypePTR) {
		t.Errorf("ValidForwardType(PTR) = true, want false — PTR is reverse-only, not a forward record_types entry")
	}
}
