package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
)

type errorBody struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

// writeJSON encodes v as the response body. Go's encoding/json HTML-
// escapes <, >, & by default — the same structural XSS mitigation
// internal/reporting's export path already relies on (see
// docs/reporting/reports.md's Content security section) — so no
// additional escaping is needed here.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError maps err to a safe JSON error body — never a raw Go error
// string, which could leak internal detail (a query, a file path). An
// *apperrors.Error's own Message is already written to be safe for a
// client (the same discipline internal/errors' doc comment describes);
// anything else becomes a generic internal-error message.
func writeError(w http.ResponseWriter, logger interface {
	Error(msg string, args ...any)
}, err error) {
	if appErr, ok := err.(*apperrors.Error); ok {
		status := appErr.HTTPStatus
		if status == 0 {
			status = http.StatusInternalServerError
		}
		if status >= 500 {
			logger.Error("api_request_failed", "category", appErr.Category, "error", appErr.Error())
		}
		writeJSON(w, status, errorResponse{Error: errorBody{Category: string(appErr.Category), Message: appErr.Message}})
		return
	}
	logger.Error("api_request_failed", "error", err.Error())
	writeJSON(w, http.StatusInternalServerError, errorResponse{Error: errorBody{Category: "internal", Message: "an unexpected error occurred"}})
}

// pathUUID parses the {id} (or other named) path value as a UUID,
// writing a 400 response and returning ok=false if it's malformed —
// every handler must check ok before proceeding.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	raw := r.PathValue(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Category: "validation", Message: name + " must be a valid UUID"}})
		return uuid.Nil, false
	}
	return id, true
}

// requiredTargetID parses the mandatory ?target_id= query parameter.
func requiredTargetID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := r.URL.Query().Get("target_id")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Category: "validation", Message: "target_id is required"}})
		return uuid.Nil, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Category: "validation", Message: "target_id must be a valid UUID"}})
		return uuid.Nil, false
	}
	return id, true
}

// optionalUUID parses an optional query parameter as a UUID; a missing
// or empty value returns uuid.Nil, true (not an error).
func optionalUUID(r *http.Request, name string) (uuid.UUID, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return uuid.Nil, nil
	}
	return uuid.Parse(raw)
}

// pagination500 is used for "list everything related to one already-
// identified entity" sub-resource fetches (an asset's own findings/
// fingerprints) where the frontend expects a plain array, not a cursor
// page — bounded by pagination.MaxLimit rather than actually unbounded.
func pagination500() pagination.Params {
	return pagination.Params{Limit: pagination.MaxLimit}
}

// paginationParams reads the shared limit/cursor query parameters,
// matching frontend/src/types/common.ts's PageParams exactly.
func paginationParams(r *http.Request) pagination.Params {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	return pagination.Params{Limit: limit, Cursor: r.URL.Query().Get("cursor")}
}
