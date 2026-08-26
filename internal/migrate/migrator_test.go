package migrate

import "testing"

func TestLoadParsesEmbeddedMigrations(t *testing.T) {
	migrations, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("expected at least one embedded migration")
	}

	for i := 1; i < len(migrations); i++ {
		if migrations[i-1].Version >= migrations[i].Version {
			t.Fatalf("migrations not sorted ascending: %d before %d", migrations[i-1].Version, migrations[i].Version)
		}
	}

	first := migrations[0]
	if first.Version != 1 {
		t.Errorf("expected first migration version 1, got %d", first.Version)
	}
	if first.SQL == "" {
		t.Error("expected migration SQL to be non-empty")
	}
}

func TestParseFilename(t *testing.T) {
	version, description, err := parseFilename("0001_init.sql")
	if err != nil {
		t.Fatalf("parseFilename returned error: %v", err)
	}
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}
	if description != "init" {
		t.Errorf("expected description %q, got %q", "init", description)
	}
}

func TestParseFilenameRejectsMissingUnderscore(t *testing.T) {
	if _, _, err := parseFilename("init.sql"); err == nil {
		t.Fatal("expected error for filename without version separator")
	}
}

func TestParseFilenameRejectsNonNumericVersion(t *testing.T) {
	if _, _, err := parseFilename("abc_init.sql"); err == nil {
		t.Fatal("expected error for non-numeric version prefix")
	}
}
