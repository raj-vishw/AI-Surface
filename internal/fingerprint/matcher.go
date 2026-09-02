package fingerprint

import "strconv"

// matchOutcome is one signature's raw match evaluation, before scoring
// and before technology normalization — the matcher's unit of work.
type matchOutcome struct {
	signature CompiledSignature
	signals   []Signal // deduplicated matched signals, declaration order
	version   string
}

// matchSignature evaluates sig's negative signals first (any match
// disqualifies the signature outright — phase6.md §10), then its
// required signals (if any is declared and doesn't match, the signature
// is disqualified — phase6.md §32), then every signal, collecting and
// deduplicating matches. ok is false when the signature does not match
// at all (no evidence, a required signal missing, or a negative signal
// present).
func matchSignature(o Observation, sig CompiledSignature) (outcome matchOutcome, ok bool) {
	for _, neg := range sig.compiledNegatives {
		if _, matched, _ := evaluateRule(o, neg); matched {
			return matchOutcome{}, false
		}
	}

	seen := make(map[string]bool)
	var signals []Signal
	var version string
	requiredCount := 0
	requiredMatched := 0

	for _, cs := range sig.compiledSignals {
		if cs.rule.Required {
			requiredCount++
		}
		value, matched, capturedVersion := evaluateRule(o, cs)
		if !matched {
			continue
		}
		if cs.rule.Required {
			requiredMatched++
		}
		matchedSignal := Signal{
			Type:        cs.rule.Type,
			Field:       cs.rule.Field,
			Value:       value,
			Weight:      cs.rule.Weight,
			Description: describeSignal(cs.rule, value),
		}
		if !seen[matchedSignal.key()] {
			seen[matchedSignal.key()] = true
			signals = append(signals, matchedSignal)
		}
		if capturedVersion != "" && version == "" {
			version = capturedVersion
		}
	}

	if requiredCount > 0 && requiredMatched < requiredCount {
		return matchOutcome{}, false
	}
	if len(signals) == 0 {
		return matchOutcome{}, false
	}

	return matchOutcome{signature: sig, signals: signals, version: version}, true
}

// evaluateRule tests one compiled signal rule against o, returning the
// matched value (for Signal.Value / explainability), whether it matched,
// and — if the rule declares a VersionGroup and it matched — the
// captured version string.
func evaluateRule(o Observation, cs compiledSignal) (value string, matched bool, version string) {
	switch cs.rule.Type {
	case SignalHTTPHeader, SignalResponseHeader, SignalRateLimitHeader:
		return testValue(cs, o.HeaderValue(cs.rule.Field))
	case SignalContentType:
		return testValue(cs, o.ContentType)
	case SignalCookieName:
		for _, name := range o.CookieNames {
			if v, ok, ver := testValue(cs, name); ok {
				return v, ok, ver
			}
		}
		return "", false, ""
	case SignalURLPath:
		return testValue(cs, o.URLPath)
	case SignalAPIPath:
		for _, p := range o.APIPaths {
			if v, ok, ver := testValue(cs, p); ok {
				return v, ok, ver
			}
		}
		return "", false, ""
	case SignalHTML, SignalHTMLMeta:
		return testValue(cs, o.HTML)
	case SignalScript:
		for _, s := range o.Scripts {
			if v, ok, ver := testValue(cs, s); ok {
				return v, ok, ver
			}
		}
		return "", false, ""
	case SignalStylesheet:
		for _, s := range o.Stylesheets {
			if v, ok, ver := testValue(cs, s); ok {
				return v, ok, ver
			}
		}
		return "", false, ""
	case SignalErrorMessage:
		return testValue(cs, o.ErrorMessage)
	case SignalJSONStructure:
		if cs.rule.Field == "model" {
			return testValue(cs, o.ExplicitModel)
		}
		for _, k := range o.JSONKeys {
			if v, ok, ver := testValue(cs, k); ok {
				return v, ok, ver
			}
		}
		return "", false, ""
	case SignalDNSCNAME:
		for _, r := range o.DNSRecords {
			if r.Type != "CNAME" {
				continue
			}
			if v, ok, ver := testValue(cs, r.Value); ok {
				return v, ok, ver
			}
		}
		return "", false, ""
	case SignalDNSRecord:
		for _, r := range o.DNSRecords {
			if cs.rule.Field != "" && r.Type != cs.rule.Field {
				continue
			}
			if v, ok, ver := testValue(cs, r.Value); ok {
				return v, ok, ver
			}
		}
		return "", false, ""
	case SignalService:
		return testValue(cs, o.Service)
	case SignalPort:
		if o.Port == nil {
			return "", false, ""
		}
		return testValue(cs, strconv.Itoa(*o.Port))
	case SignalTLS:
		return testValue(cs, tlsField(o, cs.rule.Field))
	case SignalResponseHash:
		return testValue(cs, o.ResponseHash)
	default:
		return "", false, ""
	}
}

func tlsField(o Observation, field string) string {
	switch field {
	case "version":
		return o.TLSVersion
	case "cipher_suite":
		return o.TLSCipherSuite
	case "certificate_subject":
		return o.CertificateSubject
	case "certificate_issuer":
		return o.CertificateIssuer
	default:
		return ""
	}
}

// testValue applies cs's pattern/equals condition to candidate, returning
// whether it matched and (for a pattern with a VersionGroup) the
// captured version substring.
func testValue(cs compiledSignal, candidate string) (value string, matched bool, version string) {
	if candidate == "" {
		return "", false, ""
	}
	if cs.rule.Equals != "" {
		if equalsFold(candidate, cs.rule.Equals) {
			return candidate, true, ""
		}
		return "", false, ""
	}
	if cs.re == nil {
		return "", false, ""
	}
	loc := cs.re.FindStringSubmatch(candidate)
	if loc == nil {
		return "", false, ""
	}
	if cs.rule.VersionGroup > 0 && cs.rule.VersionGroup < len(loc) {
		version = loc[cs.rule.VersionGroup]
	}
	return candidate, true, version
}

func equalsFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func describeSignal(rule SignalRule, value string) string {
	switch rule.Type {
	case SignalHTTPHeader, SignalResponseHeader, SignalRateLimitHeader:
		return rule.Field + " header matches \"" + value + "\""
	case SignalCookieName:
		return "cookie named \"" + value + "\" observed"
	case SignalDNSCNAME:
		return "CNAME target matches \"" + value + "\""
	case SignalDNSRecord:
		return rule.Field + " record value matches \"" + value + "\""
	case SignalPort:
		return "port " + value + " observed"
	case SignalService:
		return "classified service matches \"" + value + "\""
	case SignalTLS:
		return "TLS " + rule.Field + " matches \"" + value + "\""
	default:
		return string(rule.Type) + " matches \"" + value + "\""
	}
}
