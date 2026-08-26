// Package migrations embeds the platform's SQL migration files so
// internal/migrate can apply them without depending on a filesystem path
// at runtime. Physically keeping the .sql files at the repository's
// top-level migrations/ directory (rather than nested inside
// internal/migrate) matches the master specification's required layout
// and keeps the files easy for DBAs/tooling to browse independently of Go.
// The embed directive below requires this package to live alongside them.
package migrations

import "embed"

// FS holds every "<version>_<description>.sql" file in this directory.
//
//go:embed *.sql
var FS embed.FS
