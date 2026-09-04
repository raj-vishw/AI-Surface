package detectors

import (
	"context"
	"regexp"
	"strings"

	"ai-recon-platform/internal/detection"
)

// backupFileExtensionPattern matches common backup-file suffixes. Used
// only against already-discovered endpoint paths (backupFileDetector,
// below) — this project never brute-forces a wordlist of candidate
// backup filenames (phase8.md §32).
var backupFileExtensionPattern = regexp.MustCompile(`(?i)\.(bak|backup|old|orig|swp|save|tmp)$|~$`)

// backupFileDetector reports an already-discovered, already-observed
// endpoint whose path looks like a backup file (phase8.md §32) — purely
// passive: it never requests a candidate filename that discovery didn't
// already find on its own.
type backupFileDetector struct{}

func (backupFileDetector) ID() string   { return "exposed_files.backup-file" }
func (backupFileDetector) Name() string { return "Exposed Backup File" }
func (backupFileDetector) Description() string {
	return "Reports an already-discovered, reachable endpoint whose path looks like a backup file."
}
func (backupFileDetector) Version() int                 { return 1 }
func (backupFileDetector) Category() detection.Category { return detection.CategoryExposure }
func (backupFileDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d backupFileDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !ep.Observed || ep.StatusCode < 200 || ep.StatusCode >= 300 {
			continue
		}
		if !backupFileExtensionPattern.MatchString(ep.Path) {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Publicly accessible backup file",
			Description: "A reachable endpoint was already discovered whose path looks like a backup file, which may expose source code or configuration.",
			Category:    detection.CategoryExposure, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityMedium, Confidence: 0.55,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceEndpointMeta, map[string]any{
				"url": endpointLabel(ep), "path": ep.Path, "status_code": ep.StatusCode,
			}, 0.55)},
			Remediation: "Remove backup files from web-servable directories; keep them outside the document root or excluded via server configuration.",
		})
	}
	return findings, nil
}

// wellKnownExposurePaths are the ONLY paths gitExposureDetector/
// envFileExposureDetector/securityTxtDetector ever request — a small,
// fixed, hardcoded set, never a wordlist (phase8.md §29/§15).
const (
	gitHEADPath     = "/.git/HEAD"
	envFilePath     = "/.env"
	securityTxtPath = "/.well-known/security.txt"
	fetchExcerptCap = 512 // bytes read for a signature check — small: only enough to recognize the file's own format marker
)

// gitExposureDetector issues exactly one bounded GET for /.git/HEAD
// against the asset's own origin (phase8.md §30) and confirms the
// response actually looks like a git HEAD file ("ref: refs/..." or a
// 40/64-hex-char commit SHA) before reporting — never merely a 200 status,
// which many sites return for any path. It never walks the rest of the
// repository or reconstructs any source file.
type gitExposureDetector struct{}

func (gitExposureDetector) ID() string   { return "exposed_files.git-exposure" }
func (gitExposureDetector) Name() string { return "Exposed Git Metadata" }
func (gitExposureDetector) Description() string {
	return "Detects a publicly accessible .git/HEAD file via one bounded, signature-checked request."
}
func (gitExposureDetector) Version() int                 { return 1 }
func (gitExposureDetector) Category() detection.Category { return detection.CategoryExposure }
func (gitExposureDetector) Mode() detection.DetectorMode { return detection.DetectorSafeActive }

var gitHeadContentPattern = regexp.MustCompile(`^ref: refs/|^[0-9a-f]{40}$|^[0-9a-f]{64}$`)

func (d gitExposureDetector) Detect(ctx context.Context, input detection.Input) ([]detection.Finding, error) {
	if !safeActiveReady(input) {
		return nil, nil
	}
	result, err := input.Fetcher.Fetch(ctx, baseOrigin(input.Asset)+gitHEADPath, fetchExcerptCap)
	if err != nil || result.StatusCode != 200 {
		return nil, nil
	}
	body := strings.TrimSpace(string(result.Body))
	if !gitHeadContentPattern.MatchString(body) {
		return nil, nil
	}
	return []detection.Finding{{
		AssetID: input.Asset.ID, DetectorID: d.ID(), DetectorVersion: d.Version(),
		Title:       "Exposed Git metadata",
		Description: "/.git/HEAD is publicly accessible and its content matches git's own HEAD file format, indicating the repository's version-control metadata (and likely its full history) is exposed. This was not recursively downloaded or reconstructed.",
		Category:    detection.CategoryExposure, Scope: detection.ScopeAsset,
		Severity: detection.SeverityHigh, Confidence: 0.95,
		Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceResponseExcerpt, map[string]any{
			"url": baseOrigin(input.Asset) + gitHEADPath, "status_code": result.StatusCode,
			"excerpt": detection.TruncateExcerpt(body, input.Config.ExcerptLimit()),
		}, 0.95)},
		Remediation: "Remove .git from the web-servable directory (deploy from a build artifact, not the working copy) or block access to dot-directories at the web server.",
		References:  []detection.Reference{detection.ReferenceOWASPSecurityMisconfiguration},
	}}, nil
}

// envKeyPattern extracts only KEY names from a candidate .env body — never
// a value (phase8.md §31: "if the response contains apparent secrets:
// redact immediately").
var envKeyPattern = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=`)

// envFileExposureDetector issues exactly one bounded GET for /.env
// against the asset's own origin (phase8.md §31) and confirms the body
// actually looks like KEY=VALUE configuration lines before reporting.
// Only the discovered *key names* are ever recorded as evidence — every
// value is discarded immediately after the KEY= match, never stored,
// logged, or tested.
type envFileExposureDetector struct{}

func (envFileExposureDetector) ID() string   { return "exposed_files.env-file-exposure" }
func (envFileExposureDetector) Name() string { return "Exposed Environment File" }
func (envFileExposureDetector) Description() string {
	return "Detects a publicly accessible .env file via one bounded, signature-checked request; records key names only."
}
func (envFileExposureDetector) Version() int                 { return 1 }
func (envFileExposureDetector) Category() detection.Category { return detection.CategoryExposure }
func (envFileExposureDetector) Mode() detection.DetectorMode { return detection.DetectorSafeActive }

func (d envFileExposureDetector) Detect(ctx context.Context, input detection.Input) ([]detection.Finding, error) {
	if !safeActiveReady(input) {
		return nil, nil
	}
	result, err := input.Fetcher.Fetch(ctx, baseOrigin(input.Asset)+envFilePath, input.Config.ExcerptLimit())
	if err != nil || result.StatusCode != 200 {
		return nil, nil
	}
	if strings.Contains(strings.ToLower(result.ContentType), "text/html") {
		return nil, nil // almost certainly a custom error/catch-all page, not a real .env
	}
	body := string(result.Body)
	matches := envKeyPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	keys := make([]any, 0, len(matches))
	for _, m := range matches {
		keys = append(keys, m[1])
	}

	return []detection.Finding{{
		AssetID: input.Asset.ID, DetectorID: d.ID(), DetectorVersion: d.Version(),
		Title:       "Exposed environment file",
		Description: "/.env is publicly accessible and its content matches KEY=VALUE configuration format. Only variable NAMES are recorded as evidence — every value was discarded immediately and never stored or tested.",
		Category:    detection.CategoryExposure, Scope: detection.ScopeAsset,
		Severity: detection.SeverityCritical, Confidence: 0.9,
		Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceResponseExcerpt, map[string]any{
			"url": baseOrigin(input.Asset) + envFilePath, "status_code": result.StatusCode, "variable_names": keys,
		}, 0.9)},
		Remediation: "Remove .env from the web-servable directory immediately and rotate every credential it may have contained.",
		References:  []detection.Reference{detection.ReferenceOWASPSecurityMisconfiguration},
	}}, nil
}

// securityTxtDetector issues exactly one bounded GET for
// /.well-known/security.txt (phase8.md §33). A missing file is reported
// informationally only — this is a best-practice recommendation, not a
// vulnerability (phase8.md §33: "do not treat missing security.txt as a
// vulnerability unless configured").
type securityTxtDetector struct{}

func (securityTxtDetector) ID() string   { return "exposed_files.missing-security-txt" }
func (securityTxtDetector) Name() string { return "Missing security.txt" }
func (securityTxtDetector) Description() string {
	return "Checks for /.well-known/security.txt and reports informationally if absent."
}
func (securityTxtDetector) Version() int                 { return 1 }
func (securityTxtDetector) Category() detection.Category { return detection.CategoryConfiguration }
func (securityTxtDetector) Mode() detection.DetectorMode { return detection.DetectorSafeActive }

func (d securityTxtDetector) Detect(ctx context.Context, input detection.Input) ([]detection.Finding, error) {
	if !safeActiveReady(input) {
		return nil, nil
	}
	result, err := input.Fetcher.Fetch(ctx, baseOrigin(input.Asset)+securityTxtPath, fetchExcerptCap)
	if err != nil || result.StatusCode == 200 {
		return nil, nil
	}
	return []detection.Finding{{
		AssetID: input.Asset.ID, DetectorID: d.ID(), DetectorVersion: d.Version(),
		Title:       "No security.txt published",
		Description: "/.well-known/security.txt was not found. Publishing one is an optional best practice (RFC 9116) that gives researchers a documented way to report vulnerabilities — its absence is not itself a vulnerability.",
		Category:    detection.CategoryConfiguration, Scope: detection.ScopeAsset,
		Severity: detection.SeverityInformational, Confidence: 0.8,
		Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPStatus, map[string]any{
			"url": baseOrigin(input.Asset) + securityTxtPath, "status_code": result.StatusCode,
		}, 0.8)},
		Remediation: "Consider publishing /.well-known/security.txt per RFC 9116.",
	}}, nil
}
