package endpoint

import "testing"

const testHTML = `<!DOCTYPE html>
<html><head>
<link rel="stylesheet" href="/static/app.css">
<script src="/static/app.js"></script>
</head><body>
<a href="/about">About</a>
<a href="/api/users">Users</a>
<a href="/about">Duplicate</a>
<area href="/area-link">
<iframe src="/embed"></iframe>
<form method="POST" action="/login">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
<form action="/search">
  <input type="text" name="q">
</form>
</body></html>`

func TestParseHTML_Links(t *testing.T) {
	result := ParseHTML([]byte(testHTML))

	var found []string
	for _, l := range result.Links {
		found = append(found, l.URL)
	}
	want := map[string]bool{"/about": true, "/api/users": true, "/area-link": true, "/embed": true, "/static/app.css": true, "/static/app.js": true}
	for _, u := range found {
		if !want[u] {
			t.Errorf("unexpected link discovered: %q", u)
		}
	}
	for u := range want {
		present := false
		for _, f := range found {
			if f == u {
				present = true
			}
		}
		if !present {
			t.Errorf("expected link %q, not found in %v", u, found)
		}
	}
}

func TestParseHTML_Scripts(t *testing.T) {
	result := ParseHTML([]byte(testHTML))
	if len(result.Scripts) != 1 || result.Scripts[0] != "/static/app.js" {
		t.Errorf("Scripts = %v, want [/static/app.js]", result.Scripts)
	}
}

func TestParseHTML_Forms(t *testing.T) {
	result := ParseHTML([]byte(testHTML))
	if len(result.Forms) != 2 {
		t.Fatalf("len(Forms) = %d, want 2", len(result.Forms))
	}

	login := result.Forms[0]
	if login.URL != "/login" || login.Method != "POST" {
		t.Errorf("login form = %+v, want POST /login", login)
	}
	var fieldNames []string
	for _, p := range login.Parameters {
		fieldNames = append(fieldNames, p.Name)
	}
	hasUsername, hasPassword := false, false
	for _, n := range fieldNames {
		if n == "username" {
			hasUsername = true
		}
		if n == "password" {
			hasPassword = true
		}
	}
	if !hasUsername || !hasPassword {
		t.Errorf("login form fields = %v, want username and password field NAMES (never values)", fieldNames)
	}

	search := result.Forms[1]
	if search.URL != "/search" || search.Method != "GET" {
		t.Errorf("search form = %+v, want GET /search (default method)", search)
	}
}

func TestParseHTML_FormNeverCapturesValues(t *testing.T) {
	html := `<form action="/login" method="POST">
		<input type="text" name="username" value="admin">
		<input type="password" name="password" value="hunter2-should-not-appear">
	</form>`
	result := ParseHTML([]byte(html))
	if len(result.Forms) != 1 {
		t.Fatalf("expected 1 form")
	}
	if result.Forms[0].Evidence == "" {
		t.Fatal("expected non-empty evidence")
	}
	for _, forbidden := range []string{"admin", "hunter2-should-not-appear"} {
		if containsString(result.Forms[0].Evidence, forbidden) {
			t.Errorf("form evidence leaked a value: %q found in %q", forbidden, result.Forms[0].Evidence)
		}
	}
}

func TestParseHTML_MalformedDoesNotPanic(t *testing.T) {
	// golang.org/x/net/html is lenient by design (it implements the HTML5
	// parsing algorithm, which always produces *some* tree), but this
	// locks the "never panics" contract regardless.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseHTML panicked on malformed input: %v", r)
		}
	}()
	_ = ParseHTML([]byte("<html><body><a href=/unterminated<div>>>>"))
}

func containsString(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
