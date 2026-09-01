// Package pagination implements the cursor-based pagination model shared by
// every List operation in internal/repository. Keyset (cursor) pagination
// is used instead of OFFSET/LIMIT so that listing a large asset inventory
// never requires PostgreSQL to scan and discard however many rows preceded
// the requested page.
package pagination

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DefaultLimit is used when a caller requests a page without specifying a
// limit.
const DefaultLimit = 50

// MaxLimit bounds how many rows a single page may request, so a caller
// cannot accidentally (or maliciously) force an entire table into memory
// in one query.
const MaxLimit = 500

// Params is the input to a paginated List call.
type Params struct {
	// Limit is the maximum number of items to return. Values <= 0 fall
	// back to DefaultLimit; values above MaxLimit are clamped to it.
	Limit int
	// Cursor, when non-empty, resumes a listing after the row it encodes.
	// It is opaque to callers — always pass back exactly what a previous
	// Page.NextCursor returned.
	Cursor string
}

// ResolveLimit applies the Limit bounds documented on Params.
func (p Params) ResolveLimit() int {
	switch {
	case p.Limit <= 0:
		return DefaultLimit
	case p.Limit > MaxLimit:
		return MaxLimit
	default:
		return p.Limit
	}
}

// Page is the result of a paginated List call.
type Page[T any] struct {
	Items      []T
	NextCursor string // empty when there are no more items
}

// Cursor is the decoded keyset position: every List query in this project
// orders by (created_at, id) so that pagination is stable even when many
// rows share the same timestamp.
type Cursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// Encode renders c as the opaque string handed back to callers as
// Page.NextCursor.
func (c Cursor) Encode() string {
	raw := fmt.Sprintf("%s|%s", c.CreatedAt.UTC().Format(time.RFC3339Nano), c.ID.String())
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor parses a cursor string produced by Cursor.Encode. An empty
// input is not an error — it simply means "start from the beginning" — and
// returns the zero Cursor.
func DecodeCursor(cursor string) (Cursor, error) {
	if cursor == "" {
		return Cursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return Cursor{}, fmt.Errorf("invalid cursor encoding: %w", err)
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		return Cursor{}, fmt.Errorf("invalid cursor format")
	}
	ts, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return Cursor{}, fmt.Errorf("invalid cursor timestamp: %w", err)
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return Cursor{}, fmt.Errorf("invalid cursor id: %w", err)
	}
	return Cursor{CreatedAt: ts, ID: id}, nil
}
