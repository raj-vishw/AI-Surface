package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// RecordType identifies a DNS resource record type. Stable string
// identifiers, matching the project's other domain enums.
type RecordType string

// Recognized forward-query record types (phase5.md §10) plus PTR, which is
// used only for reverse (IP -> name) lookups — see Resolver.LookupPTR.
const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeNS    RecordType = "NS"
	TypeTXT   RecordType = "TXT"
	TypeSOA   RecordType = "SOA"
	TypeCAA   RecordType = "CAA"
	TypePTR   RecordType = "PTR"
)

// forwardRecordTypes are the types valid in configuration's record_types
// list (a forward query for a domain name) — PTR is deliberately excluded,
// matching config.validDNSRecordTypes.
var forwardRecordTypes = map[RecordType]bool{
	TypeA: true, TypeAAAA: true, TypeCNAME: true, TypeMX: true,
	TypeNS: true, TypeTXT: true, TypeSOA: true, TypeCAA: true,
}

// ValidForwardType reports whether t is a valid entry in a forward
// record_types list.
func ValidForwardType(t RecordType) bool { return forwardRecordTypes[t] }

// SOAData holds an SOA record's structured fields (phase5.md §18).
type SOAData struct {
	PrimaryNS  string
	Mailbox    string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	MinimumTTL uint32
}

// CAAData holds a CAA record's structured fields (phase5.md §17).
type CAAData struct {
	Flag  uint8
	Tag   string
	Value string
}

// Record is the normalized internal representation of one DNS resource
// record (phase5.md §10). Fields that don't apply to every record type
// are nil/zero rather than present-but-meaningless — e.g. Priority is only
// set for MX.
type Record struct {
	Name string
	Type RecordType
	TTL  uint32
	// Value is the record's primary normalized value: the IP for A/AAAA,
	// the target hostname for CNAME/NS/PTR, the mail server for MX, the
	// text content for TXT.
	Value string
	// Priority is MX's preference value; nil for every other type.
	Priority *int
	SOA      *SOAData
	CAA      *CAAData
}

// Identity returns Record's deterministic natural key: name + type +
// normalized value + priority where applicable (phase5.md §39). Never
// scan_id, a timestamp, or a random UUID — two observations with the same
// Identity are the same logical record.
func (r Record) Identity() string {
	priority := ""
	if r.Priority != nil {
		priority = strconv.Itoa(*r.Priority)
	}
	return fmt.Sprintf("%s|%s|%s|%s", r.Name, r.Type, r.Value, priority)
}

// Fingerprint is the SHA-256 hex digest of Identity — a fixed-size key
// suitable for map/set deduplication of records seen within one scan.
func (r Record) Fingerprint() string {
	sum := sha256.Sum256([]byte(r.Identity()))
	return hex.EncodeToString(sum[:])
}
