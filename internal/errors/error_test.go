package errors

import (
	stderrors "errors"
	"net/http"
	"testing"
)

func TestNewSetsDefaultHTTPStatus(t *testing.T) {
	cases := map[Category]int{
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

	for category, want := range cases {
		err := New(category, "boom", nil)
		if err.HTTPStatus != want {
			t.Errorf("category %s: got status %d, want %d", category, err.HTTPStatus, want)
		}
	}
}

func TestWrapIsSynonymForNew(t *testing.T) {
	cause := stderrors.New("connection refused")
	err := Wrap(CategoryDatabase, "failed to load target", cause)

	if err.Category != CategoryDatabase {
		t.Errorf("expected category database, got %s", err.Category)
	}
	if !stderrors.Is(err, cause) {
		t.Fatalf("expected errors.Is to find the wrapped cause")
	}
}

func TestErrorPreservesCause(t *testing.T) {
	cause := stderrors.New("connection refused")
	err := NewInternal("failed to connect", cause)

	if !stderrors.Is(err, cause) {
		t.Fatalf("expected errors.Is to find the wrapped cause")
	}

	if got := err.Error(); got != "failed to connect: connection refused" {
		t.Errorf("unexpected Error() output: %q", got)
	}
}

func TestClientMessageHidesInternalDetails(t *testing.T) {
	cause := stderrors.New("password authentication failed for user \"admin\"")
	err := NewInternal("database connection failed", cause)

	if got := err.ClientMessage(); got != "an internal error occurred" {
		t.Errorf("internal error leaked details to client: %q", got)
	}

	dbErr := NewDatabase("query failed", cause)
	if got := dbErr.ClientMessage(); got != "an internal error occurred" {
		t.Errorf("database error leaked details to client: %q", got)
	}

	configErr := NewConfiguration("bad config", cause)
	if got := configErr.ClientMessage(); got != "an internal error occurred" {
		t.Errorf("configuration error leaked details to client: %q", got)
	}

	validationErr := NewValidation("target is required", nil)
	if got := validationErr.ClientMessage(); got != "target is required" {
		t.Errorf("validation message should be exposed as-is, got %q", got)
	}
}

func TestWithHTTPStatusOverride(t *testing.T) {
	err := NewValidation("bad input", nil).WithHTTPStatus(http.StatusTeapot)
	if err.HTTPStatus != http.StatusTeapot {
		t.Errorf("expected overridden status %d, got %d", http.StatusTeapot, err.HTTPStatus)
	}
}

func TestHTTPStatusHelper(t *testing.T) {
	wrapped := stderrors.New("plain error")
	if got := HTTPStatus(wrapped); got != http.StatusInternalServerError {
		t.Errorf("plain errors should default to 500, got %d", got)
	}

	appErr := NewNotFound("asset not found", nil)
	if got := HTTPStatus(appErr); got != http.StatusNotFound {
		t.Errorf("expected 404, got %d", got)
	}
}

func TestAsExtractsWrappedError(t *testing.T) {
	inner := NewConflict("scan already running", nil)
	outer := stderrors.New("wrap: " + inner.Error())

	if _, ok := As(outer); ok {
		t.Fatalf("As should not find an *Error inside a plain wrapped string")
	}

	if _, ok := As(inner); !ok {
		t.Fatalf("As should find the *Error itself")
	}
}
