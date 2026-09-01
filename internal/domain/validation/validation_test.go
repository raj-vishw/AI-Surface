package validation

import "testing"

func TestErrors_ErrOrNil(t *testing.T) {
	var empty Errors
	if empty.ErrOrNil() != nil {
		t.Error("empty Errors should produce a nil error")
	}

	withErr := empty.Add("field", "message")
	if withErr.ErrOrNil() == nil {
		t.Error("non-empty Errors should produce a non-nil error")
	}
}

func TestErrors_Error(t *testing.T) {
	var errs Errors
	errs = errs.Add("name", "must not be empty")
	errs = errs.Add("type", "must be recognized")

	msg := errs.Error()
	if msg == "" {
		t.Fatal("expected a non-empty message")
	}
}

func TestErrors_HasErrors(t *testing.T) {
	var empty Errors
	if empty.HasErrors() {
		t.Error("empty Errors.HasErrors() should be false")
	}
	if !empty.Add("f", "m").HasErrors() {
		t.Error("non-empty Errors.HasErrors() should be true")
	}
}
