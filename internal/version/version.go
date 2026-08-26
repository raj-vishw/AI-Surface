// Package version exposes build-time version information. Values are
// injected via -ldflags at build time (see Makefile); the fallbacks below
// are used for `go run` and unlinked test binaries.
package version

var (
	// Version is the semantic version of the build, e.g. "0.1.0".
	Version = "0.0.0-dev"
	// Commit is the git commit SHA the binary was built from.
	Commit = "unknown"
	// BuildDate is the RFC3339 timestamp the binary was built at.
	BuildDate = "unknown"
)

// Info is a structured snapshot of the build metadata above.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

// Get returns the current build Info.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
	}
}
