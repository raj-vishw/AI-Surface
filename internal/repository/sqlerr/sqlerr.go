// Package sqlerr translates low-level PostgreSQL/pgx errors into the
// platform's typed error model (internal/errors), shared by every
// repository package so a raw SQL error never reaches a service or HTTP
// handler.
package sqlerr

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	apperrors "ai-recon-platform/internal/errors"
)

// PostgreSQL SQLSTATE codes this package recognizes and maps to a specific
// error category. Anything else falls back to CategoryDatabase.
const (
	uniqueViolation     = "23505"
	foreignKeyViolation = "23503"
	checkViolation      = "23514"
)

// Translate converts err into an *errors.Error appropriate for action
// (a short description used in the message, e.g. "creating asset"). A nil
// err returns nil — every repository method ends a rows.Err() check with
// `return items, sqlerr.Translate(rows.Err(), "iterating ...")` on its
// success path, so Translate must be a no-op on nil or every one of those
// callers would always return a non-nil error, even having found nothing
// wrong. Constraint violations become CategoryConflict/CategoryValidation
// so callers can distinguish "you asked for something that already exists
// / references something missing" from a genuine infrastructure failure;
// everything else becomes CategoryDatabase, whose message and cause are
// never exposed to clients (see errors.Error.ClientMessage).
func Translate(err error, action string) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case uniqueViolation:
			return apperrors.NewConflict(action+": duplicate value", err)
		case foreignKeyViolation:
			return apperrors.NewValidation(action+": referenced row does not exist", err)
		case checkViolation:
			return apperrors.NewValidation(action+": violates a database constraint", err)
		}
	}
	return apperrors.NewDatabase(action, err)
}
