package detection

// Shared references reused by more than one built-in detector (in
// internal/detection/detectors) — kept here as a small exported set
// rather than a central per-detector-id lookup table, so each detector's
// own file still stays the single place its logic, severity rationale,
// and remediation text live together (phase8.md §42: "keep detector logic
// understandable... do not build an opaque rules engine"); this file only
// avoids re-typing the same handful of stable external URLs in more than
// one detector.
var (
	ReferenceOWASPSecurityMisconfiguration = Reference{
		Label: "OWASP", URL: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
	}
	ReferenceOWASPCryptographicFailures = Reference{
		Label: "OWASP", URL: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
	}
	ReferenceOWASPIdentificationAuthFailures = Reference{
		Label: "OWASP", URL: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
	}
	ReferenceOWASPVulnerableComponents = Reference{
		Label: "OWASP", URL: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
	}
	ReferenceMDNCSP = Reference{
		Label: "MDN", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
	}
	ReferenceMDNHSTS = Reference{
		Label: "MDN", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
	}
	ReferenceMDNCORS = Reference{
		Label: "MDN", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
	}
	ReferenceMDNSetCookie = Reference{
		Label: "MDN", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
	}
	ReferenceRFC6797 = Reference{Label: "RFC 6797", URL: "https://www.rfc-editor.org/rfc/rfc6797"}
)
