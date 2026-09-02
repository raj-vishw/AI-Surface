package fingerprint

import (
	"embed"
	"io/fs"
)

// DefaultSignaturesFS holds the platform's built-in signature set
// (internal/fingerprint/signatures/*.yaml), embedded so the engine works
// without depending on a filesystem path at runtime — mirroring
// migrations.FS's same rationale for SQL migrations. An operator may
// instead point fingerprint.signatures_path at an external directory to
// use a custom or extended set (see internal/config.FingerprintConfig);
// LoadSignatures accepts any fs.FS, not just this embedded one.
//
//go:embed signatures/*.yaml
var DefaultSignaturesFS embed.FS

// LoadDefaultSignatures loads the platform's built-in signature set. It
// exists so callers never need to know DefaultSignaturesFS's internal
// "signatures/" subdirectory layout (LoadSignatures itself expects
// "*.yaml" files directly at the given fs.FS's root — true for an
// operator-supplied external directory, but embed.FS always keeps its
// directory structure, hence the fs.Sub here).
func LoadDefaultSignatures() ([]CompiledSignature, error) {
	sub, err := fs.Sub(DefaultSignaturesFS, "signatures")
	if err != nil {
		return nil, err
	}
	return LoadSignatures(sub)
}
