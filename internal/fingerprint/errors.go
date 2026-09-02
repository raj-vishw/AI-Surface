package fingerprint

import "fmt"

// SignatureError reports a problem with one signature definition,
// identified by its source file and (when known) its Name — loading
// fails clearly and names the offending signature rather than silently
// skipping it (phase6.md §28).
type SignatureError struct {
	File    string
	Name    string
	Message string
}

func (e *SignatureError) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("signature %q in %s: %s", e.Name, e.File, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.File, e.Message)
}
