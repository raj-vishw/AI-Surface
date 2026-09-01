// Package validation provides a small, structured validation-error type
// shared by every domain package (target, asset, endpoint). It exists so
// that Validate() methods across the codebase — including future discovery
// and scanning components — return a consistent, machine-inspectable shape
// instead of ad hoc error strings.
package validation

import "strings"

// FieldError reports a single invalid field.
type FieldError struct {
	Field   string
	Message string
}

// Errors is an ordered collection of FieldError. A nil or empty Errors is
// not a failure — check HasErrors (or compare len(errs) == 0) before
// treating a Validate() result as an error.
type Errors []FieldError

// Add appends a field error and returns the updated slice, so callers can
// write `errs = errs.Add("field", "message")`.
func (e Errors) Add(field, message string) Errors {
	return append(e, FieldError{Field: field, Message: message})
}

// HasErrors reports whether any field errors were recorded.
func (e Errors) HasErrors() bool {
	return len(e) > 0
}

// Error implements the error interface, joining every field error into a
// single human-readable message. Callers that need the structured form
// should type-assert to validation.Errors rather than parsing this string.
func (e Errors) Error() string {
	parts := make([]string, 0, len(e))
	for _, fe := range e {
		parts = append(parts, fe.Field+": "+fe.Message)
	}
	return strings.Join(parts, "; ")
}

// ErrOrNil returns e as an error if it has any entries, or nil otherwise.
// Validate() methods use this so they can always build an Errors value and
// return a plain, comparable-to-nil error at the end.
func (e Errors) ErrOrNil() error {
	if e.HasErrors() {
		return e
	}
	return nil
}
