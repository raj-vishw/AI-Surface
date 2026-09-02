package fingerprint

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestLoadDefaultSignatures(t *testing.T) {
	sigs, err := LoadDefaultSignatures()
	if err != nil {
		t.Fatalf("LoadDefaultSignatures: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("expected at least one built-in signature")
	}
	for _, s := range sigs {
		if s.Name == "" {
			t.Errorf("signature with empty name in loaded set")
		}
		if !s.Category.Valid() {
			t.Errorf("signature %q has invalid category %q", s.Name, s.Category)
		}
	}
	// Sorted by name.
	for i := 1; i < len(sigs); i++ {
		if sigs[i-1].Name >= sigs[i].Name {
			t.Errorf("signatures not sorted: %q >= %q", sigs[i-1].Name, sigs[i].Name)
		}
	}
}

func TestLoadSignatures_MalformedYAML(t *testing.T) {
	dir := fstest.MapFS{
		"bad.yaml": &fstest.MapFile{Data: []byte("signatures: [not: valid: yaml: at: all")},
	}
	if _, err := LoadSignatures(dir); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestLoadSignatures_MissingName(t *testing.T) {
	dir := fstest.MapFS{
		"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - category: web_server
    signals:
      - type: http_header
        field: Server
        pattern: "^nginx"
        weight: 0.9
`)},
	}
	_, err := LoadSignatures(dir)
	if err == nil {
		t.Fatal("expected an error for a signature with no name")
	}
	if sigErr, ok := err.(*SignatureError); !ok || sigErr.Message != "missing name" {
		t.Errorf("error = %v, want a SignatureError about a missing name", err)
	}
}

func TestLoadSignatures_MissingCategory(t *testing.T) {
	dir := fstest.MapFS{
		"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: broken
    signals:
      - type: http_header
        field: Server
        pattern: "^nginx"
        weight: 0.9
`)},
	}
	if _, err := LoadSignatures(dir); err == nil {
		t.Fatal("expected an error for a signature with no category")
	}
}

func TestLoadSignatures_InvalidCategory(t *testing.T) {
	dir := fstest.MapFS{
		"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: broken
    category: not_a_real_category
    signals:
      - type: http_header
        field: Server
        pattern: "^nginx"
        weight: 0.9
`)},
	}
	if _, err := LoadSignatures(dir); err == nil {
		t.Fatal("expected an error for an unrecognized category")
	}
}

func TestLoadSignatures_DuplicateName(t *testing.T) {
	dir := fstest.MapFS{
		"a.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: dup
    category: web_server
    signals:
      - {type: http_header, field: Server, pattern: "^nginx", weight: 0.9}
`)},
		"b.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: dup
    category: web_server
    signals:
      - {type: http_header, field: Server, pattern: "^apache", weight: 0.9}
`)},
	}
	_, err := LoadSignatures(dir)
	if err == nil {
		t.Fatal("expected an error for a duplicate signature name across files")
	}
}

func TestLoadSignatures_InvalidRegex(t *testing.T) {
	dir := fstest.MapFS{
		"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: broken
    category: web_server
    signals:
      - {type: http_header, field: Server, pattern: "(unclosed", weight: 0.9}
`)},
	}
	if _, err := LoadSignatures(dir); err == nil {
		t.Fatal("expected an error for an invalid regex")
	}
}

func TestLoadSignatures_InvalidWeight(t *testing.T) {
	tests := []string{"0", "-0.5", "1.5"}
	for _, w := range tests {
		dir := fstest.MapFS{
			"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: broken
    category: web_server
    signals:
      - {type: http_header, field: Server, pattern: "^nginx", weight: ` + w + `}
`)},
		}
		if _, err := LoadSignatures(dir); err == nil {
			t.Errorf("weight=%s: expected an error for an out-of-range weight", w)
		}
	}
}

func TestLoadSignatures_UnsupportedSignalType(t *testing.T) {
	dir := fstest.MapFS{
		"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: broken
    category: web_server
    signals:
      - {type: carrier_pigeon, field: Server, pattern: "^nginx", weight: 0.9}
`)},
	}
	if _, err := LoadSignatures(dir); err == nil {
		t.Fatal("expected an error for an unsupported signal type")
	}
}

func TestLoadSignatures_NoSignals(t *testing.T) {
	dir := fstest.MapFS{
		"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: broken
    category: web_server
    signals: []
`)},
	}
	if _, err := LoadSignatures(dir); err == nil {
		t.Fatal("expected an error for a signature with no signals")
	}
}

func TestLoadSignatures_VersionGroupOutOfRange(t *testing.T) {
	dir := fstest.MapFS{
		"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: broken
    category: web_server
    signals:
      - {type: http_header, field: Server, pattern: "^nginx", weight: 0.9, version_group: 5}
`)},
	}
	if _, err := LoadSignatures(dir); err == nil {
		t.Fatal("expected an error when version_group exceeds the pattern's capture groups")
	}
}

func TestLoadSignatures_BothPatternAndEquals(t *testing.T) {
	dir := fstest.MapFS{
		"x.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: broken
    category: web_server
    signals:
      - {type: port, field: "", pattern: "^80$", equals: "80", weight: 0.9}
`)},
	}
	if _, err := LoadSignatures(dir); err == nil {
		t.Fatal("expected an error when both pattern and equals are set")
	}
}

func TestLoadSignatures_SortedLoadOrder(t *testing.T) {
	dir := fstest.MapFS{
		"z.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: zzz
    category: web_server
    signals: [{type: http_header, field: Server, pattern: "^z", weight: 0.9}]
`)},
		"a.yaml": &fstest.MapFile{Data: []byte(`
signatures:
  - name: aaa
    category: web_server
    signals: [{type: http_header, field: Server, pattern: "^a", weight: 0.9}]
`)},
	}
	sigs, err := LoadSignatures(dir)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	if len(sigs) != 2 || sigs[0].Name != "aaa" || sigs[1].Name != "zzz" {
		t.Fatalf("expected sorted [aaa zzz], got %v", names(sigs))
	}
}

func names(sigs []CompiledSignature) []string {
	out := make([]string, len(sigs))
	for i, s := range sigs {
		out[i] = s.Name
	}
	return out
}

var _ fs.FS = fstest.MapFS{}
