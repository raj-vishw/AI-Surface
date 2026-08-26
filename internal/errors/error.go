// Package errors defines the platform's internal error model.
//
// Every error that crosses a service boundary should be (or be wrapped as)
// an *errors.Error so that callers can rely on a consistent category and
// HTTP status, while the original cause is preserved for logging and
// debugging without being leaked to API clients.
//
// Because this package's name collides with the standard library's
// "errors", callers should import it under an alias, conventionally
// "apperrors":
//
//	import apperrors "ai-recon-platform/internal/errors"
package errors

import (
	stderrors "errors"
	"fmt"
	"net/http"
)

// Category classifies an error independently of its transport (HTTP, CLI, gRPC, ...).
type Category string

// Recognized error categories. Every *Error has exactly one.
const (
	CategoryValidation    Category = "validation"
	CategoryConfiguration Category = "configuration"
	CategoryDatabase      Category = "database"
	CategoryNetwork       Category = "network"
	CategoryHTTP          Category = "http"
	CategoryAuthorization Category = "authorization"
	CategoryNotFound      Category = "not_found"
	CategoryUnauthorized  Category = "unauthorized"
	CategoryForbidden     Category = "forbidden"
	CategoryConflict      Category = "conflict"
	CategoryUnavailable   Category = "unavailable"
	CategoryTimeout       Category = "timeout"
	CategoryInternal      Category = "internal"
)

// defaultHTTPStatus maps a category to its default HTTP status code.
// A specific error may still override this via WithHTTPStatus.
var defaultHTTPStatus = map[Category]int{
	CategoryValidation:    http.StatusBadRequest,
	CategoryConfiguration: http.StatusInternalServerError,
	CategoryDatabase:      http.StatusInternalServerError,
	CategoryNetwork:       http.StatusBadGateway,
	CategoryHTTP:          http.StatusBadGateway,
	CategoryAuthorization: http.StatusUnauthorized,
	CategoryNotFound:      http.StatusNotFound,
	CategoryUnauthorized:  http.StatusUnauthorized,
	CategoryForbidden:     http.StatusForbidden,
	CategoryConflict:      http.StatusConflict,
	CategoryUnavailable:   http.StatusServiceUnavailable,
	CategoryTimeout:       http.StatusGatewayTimeout,
	CategoryInternal:      http.StatusInternalServerError,
}

// Error is the platform's internal error type. It preserves the original
// cause, a stable category, a human-readable message, and the HTTP status
// that should be reported to API clients.
type Error struct {
	Cause      error
	Category   Category
	Message    string
	HTTPStatus int
}

// Error implements the error interface. It intentionally includes the
// underlying cause for logging; callers that render errors to end users
// must use Message (or ClientMessage) instead of Error().
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap allows errors.Is / errors.As to traverse into the cause.
func (e *Error) Unwrap() error {
	return e.Cause
}

// ClientMessage returns the message that is safe to expose to external
// callers. Internal, database, and configuration category errors never
// leak their message or cause to clients; everything else surfaces its
// Message.
func (e *Error) ClientMessage() string {
	switch e.Category {
	case CategoryInternal, CategoryDatabase, CategoryConfiguration:
		return "an internal error occurred"
	default:
		return e.Message
	}
}

// New constructs an *Error with the default HTTP status for the category.
func New(category Category, message string, cause error) *Error {
	status, ok := defaultHTTPStatus[category]
	if !ok {
		status = http.StatusInternalServerError
	}
	return &Error{
		Cause:      cause,
		Category:   category,
		Message:    message,
		HTTPStatus: status,
	}
}

// Wrap is a synonym for New, matching the master specification's example
// usage (apperrors.Wrap(apperrors.CategoryDatabase, "message", err)).
func Wrap(category Category, message string, cause error) *Error {
	return New(category, message, cause)
}

// WithHTTPStatus returns a copy of e with an overridden HTTP status.
func (e *Error) WithHTTPStatus(status int) *Error {
	clone := *e
	clone.HTTPStatus = status
	return &clone
}

// Convenience constructors for the most common categories.

// NewValidation builds a CategoryValidation error (HTTP 400).
func NewValidation(message string, cause error) *Error {
	return New(CategoryValidation, message, cause)
}

// NewConfiguration builds a CategoryConfiguration error (HTTP 500). Its
// message and cause are never exposed to clients; see ClientMessage.
func NewConfiguration(message string, cause error) *Error {
	return New(CategoryConfiguration, message, cause)
}

// NewDatabase builds a CategoryDatabase error (HTTP 500). Its message and
// cause are never exposed to clients; see ClientMessage — driver errors
// must never reach API users directly.
func NewDatabase(message string, cause error) *Error {
	return New(CategoryDatabase, message, cause)
}

// NewNetwork builds a CategoryNetwork error (HTTP 502).
func NewNetwork(message string, cause error) *Error {
	return New(CategoryNetwork, message, cause)
}

// NewHTTP builds a CategoryHTTP error (HTTP 502) for failures talking to an
// upstream HTTP service.
func NewHTTP(message string, cause error) *Error {
	return New(CategoryHTTP, message, cause)
}

// NewAuthorization builds a CategoryAuthorization error (HTTP 401).
func NewAuthorization(message string, cause error) *Error {
	return New(CategoryAuthorization, message, cause)
}

// NewNotFound builds a CategoryNotFound error (HTTP 404).
func NewNotFound(message string, cause error) *Error {
	return New(CategoryNotFound, message, cause)
}

// NewUnauthorized builds a CategoryUnauthorized error (HTTP 401).
func NewUnauthorized(message string, cause error) *Error {
	return New(CategoryUnauthorized, message, cause)
}

// NewForbidden builds a CategoryForbidden error (HTTP 403).
func NewForbidden(message string, cause error) *Error {
	return New(CategoryForbidden, message, cause)
}

// NewConflict builds a CategoryConflict error (HTTP 409).
func NewConflict(message string, cause error) *Error {
	return New(CategoryConflict, message, cause)
}

// NewUnavailable builds a CategoryUnavailable error (HTTP 503).
func NewUnavailable(message string, cause error) *Error {
	return New(CategoryUnavailable, message, cause)
}

// NewTimeout builds a CategoryTimeout error (HTTP 504).
func NewTimeout(message string, cause error) *Error {
	return New(CategoryTimeout, message, cause)
}

// NewInternal builds a CategoryInternal error (HTTP 500). Its message and
// cause are never exposed to clients; see ClientMessage.
func NewInternal(message string, cause error) *Error {
	return New(CategoryInternal, message, cause)
}

// As extracts an *Error from err, if present in its chain.
func As(err error) (*Error, bool) {
	var target *Error
	if stderrors.As(err, &target) {
		return target, true
	}
	return nil, false
}

// HTTPStatus returns the HTTP status that should be reported for err. If err
// is not (or does not wrap) an *Error, it defaults to 500.
func HTTPStatus(err error) int {
	if e, ok := As(err); ok {
		if e.HTTPStatus != 0 {
			return e.HTTPStatus
		}
		return defaultHTTPStatus[e.Category]
	}
	return http.StatusInternalServerError
}
