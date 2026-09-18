package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// R-154 (CL-BUG-083) — every language must get its OWN template.
//
// `PLAYGROUND_TEMPLATES` in static/app.js carried source for exactly two of the
// nine surfaces (java, ts) and `loadTemplate` ended with
// `|| PLAYGROUND_TEMPLATES.java`. Pick Ruby, click Load Template, get Java. The
// fallback is silent: nothing in the UI says the template is for another
// language, and the filename sent to /api/compile is still `P2PKH.runar.rb`,
// so the user sees a parse error against source they did not write.
//
// The fix is not seven more string literals in a JS file — that is the same
// drift waiting to happen, one copy per language. The webapp already resolves a
// real PriceBet source per language from disk for `compilePriceBet`, and those
// nine files are compiled by the app itself on every round. The template
// endpoint serves the same bytes, so a template that stops compiling is a
// broken example contract, not a stale copy in a script tag.

func getTemplate(t *testing.T, lang string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/template?lang="+lang, nil)
	rec := httptest.NewRecorder()
	handleTemplate(rec, req)

	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode (%d): %v\nbody: %s", rec.Code, err, rec.Body.String())
	}
	return rec.Code, decoded
}

// Each language's template must contain something only that surface has, so a
// fallback to another language's source cannot satisfy the assertion.
var templateFingerprints = map[string]struct {
	ext      string
	contains []string
}{
	"ts":   {".runar.ts", []string{"class PriceBet", "readonly"}},
	"sol":  {".runar.sol", []string{"contract PriceBet"}},
	"move": {".runar.move", []string{"module"}},
	"go":   {".runar.go", []string{"package ", "func "}},
	"rs":   {".runar.rs", []string{"struct PriceBet", "impl "}},
	"py":   {".runar.py", []string{"class PriceBet", "def "}},
	"rb":   {".runar.rb", []string{"class PriceBet", "def "}},
	"zig":  {".runar.zig", []string{"const PriceBet", "pub fn "}},
	"java": {".runar.java", []string{"class PriceBet", "@Public"}},
}

func TestTemplate_EveryLanguageGetsItsOwnSource(t *testing.T) {
	for lang, want := range templateFingerprints {
		t.Run(lang, func(t *testing.T) {
			code, resp := getTemplate(t, lang)
			if code != http.StatusOK {
				t.Fatalf("template %s failed (%d): %v", lang, code, resp)
			}

			filename, _ := resp["filename"].(string)
			if !strings.HasSuffix(filename, want.ext) {
				t.Fatalf("template %s returned filename %q, want a %s file", lang, filename, want.ext)
			}

			source, _ := resp["source"].(string)
			if strings.TrimSpace(source) == "" {
				t.Fatalf("template %s returned empty source", lang)
			}
			for _, needle := range want.contains {
				if !strings.Contains(source, needle) {
					t.Fatalf("template %s does not contain %q — this looks like another language's source:\n%s",
						lang, needle, source[:min(len(source), 300)])
				}
			}
		})
	}
}

func TestTemplate_NoTwoLanguagesShareSource(t *testing.T) {
	// The bug was a silent fallback, which shows up as two languages returning
	// byte-identical source. Nothing else in the suite would notice.
	seen := map[string]string{}
	for lang := range templateFingerprints {
		_, resp := getTemplate(t, lang)
		source, _ := resp["source"].(string)
		if other, dup := seen[source]; dup {
			t.Fatalf("languages %s and %s returned identical template source", other, lang)
		}
		seen[source] = lang
	}
	if len(seen) != len(templateFingerprints) {
		t.Fatalf("got %d distinct templates for %d languages", len(seen), len(templateFingerprints))
	}
}

func TestTemplate_ServedSourceActuallyCompiles(t *testing.T) {
	// A template that does not compile is worse than no template: the user's
	// first action in the playground fails through no fault of their own.
	for lang := range templateFingerprints {
		t.Run(lang, func(t *testing.T) {
			_, resp := getTemplate(t, lang)
			source, _ := resp["source"].(string)
			filename, _ := resp["filename"].(string)
			if _, _, _, err := compileSource([]byte(source), filename); err != nil {
				t.Fatalf("template for %s does not compile: %v", lang, err)
			}
		})
	}
}

func TestTemplate_RejectsUnknownLanguage(t *testing.T) {
	// normalizeLang silently maps anything unrecognised to "ts". For COMPILING
	// that is a harmless default; for a template request it would reinstate the
	// exact bug — asking for a language you do not get, with no indication.
	code, resp := getTemplate(t, "cobol")
	if code == http.StatusOK {
		t.Fatalf("unknown lang returned 200 with %v", resp)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
