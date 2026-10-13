// Byte-identical golden diff harness for the Go compiler.
//
// For every directory under `conformance/tests/`, this test:
//  1. Locates the Go-format source file (`*.runar.go`)
//  2. Compiles it via the native Go compiler API (CompileSourceToIR + CompileFromSource)
//  3. Canonicalizes the ANF IR JSON (sort keys, strip `sourceLoc`, 2-space indent)
//  4. Asserts byte-for-byte equality against `expected-ir.json` and `expected-script.hex`
//
// This supplements the indirect runtime-TS runner in `conformance/runner/runner.ts`
// with a native Go-side check driven from the shared conformance corpus.
//
// The canonicalization strategy mirrors
// `conformance/runner/runner.ts::canonicalizeJson`.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
)

// Resolve the Go-format source file for a conformance fixture.
//
// Mirrors the TS runner (conformance/runner/runner.ts):
//  1. If `source.json` exists and has a `.runar.go` entry in `sources`,
//     resolve it relative to the fixture directory. Use it if it exists.
//  2. Otherwise fall back to the first `*.runar.go` file in the fixture dir.
func findGoSource(testDir string) string {
	// (1) source.json lookup
	configPath := filepath.Join(testDir, "source.json")
	if raw, err := os.ReadFile(configPath); err == nil {
		var cfg struct {
			Sources map[string]string `json:"sources"`
		}
		if json.Unmarshal(raw, &cfg) == nil {
			if rel, ok := cfg.Sources[".runar.go"]; ok && rel != "" {
				resolved := filepath.Clean(filepath.Join(testDir, rel))
				if _, err := os.Stat(resolved); err == nil {
					return resolved
				}
			}
		}
	}

	// (2) glob fallback in fixture directory
	entries, err := os.ReadDir(testDir)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".runar.go") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return filepath.Join(testDir, names[0])
}

// canonicalizeValue recursively sorts object keys and strips `sourceLoc`.
// Returns the canonicalized value.
func canonicalizeValue(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			if k == "sourceLoc" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// Preserve insertion order by using an ordered slice-of-pairs
		// through json.Marshal via a custom marshaler. Since the standard
		// map keys are sorted by `json.Marshal` anyway, we can keep it simple:
		// just rebuild the map.
		out := make(map[string]interface{}, len(keys))
		for _, k := range keys {
			out[k] = canonicalizeValue(x[k])
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, y := range x {
			out[i] = canonicalizeValue(y)
		}
		return out
	default:
		return v
	}
}

// Serialize a canonicalized value to pretty-printed JSON (2-space indent).
// `encoding/json` sorts map keys alphabetically when marshaling, so the result
// is deterministic.
func canonicalizeJSON(raw []byte) (string, error) {
	var parsed interface{}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber() // preserve bigint representation
	if err := dec.Decode(&parsed); err != nil {
		return "", fmt.Errorf("parse JSON: %w", err)
	}
	canon := canonicalizeValue(parsed)
	out, err := json.MarshalIndent(canon, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal JSON: %w", err)
	}
	return string(out), nil
}

type fixtureFailure struct {
	name     string
	kind     string
	expected string
	actual   string
}

// fixtureAllowlistedForGo honors the per-fixture compiler allowlist in
// `source.json`. If `compilers` is present and does not include "go", the
// fixture is intentionally opted out of Go Stack-IR / hex parity (parser
// coverage is universal and enforced elsewhere). Mirrors the Rust harness's
// `fixture_allowlisted_for_rust` (F-285) and the Ruby harness's
// `read_compiler_allowlist` (F-151). See `conformance/README.md` ⇒
// "Per-fixture compiler allowlist".
func fixtureAllowlistedForGo(testDir string) bool {
	configPath := filepath.Join(testDir, "source.json")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return true
	}
	var cfg struct {
		Compilers []string `json:"compilers"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return true
	}
	if cfg.Compilers == nil {
		return true
	}
	for _, c := range cfg.Compilers {
		if c == "go" {
			return true
		}
	}
	return false
}

// scanFixtures walks `dirs` (conformance fixture directories) and classifies
// each one, compiling via the native Go compiler API. Extracted from
// TestConformanceGoldens so the classification logic is directly
// unit-testable against synthetic fixture directories (N-124), without
// depending on or risking the real conformance corpus.
//
// Classification (N-124 fix, porting F-151's scan semantics):
//   - A fixture whose source.json `compilers` allowlist excludes "go" is
//     SKIPPED outright (go is not a required conformance target for it).
//   - Any other fixture with no resolvable `.runar.go` source is a FAILURE
//     (kind "missing-source"). Before this fix, such fixtures were
//     collected into a `missing` bucket that the final assertion never
//     consulted, so a fixture whose source resolution failed reported
//     "0 fail" instead of failing.
//   - A fixture whose source compiles but ships no `expected-ir.json` or
//     no `expected-script.hex` is a FAILURE (handled by compareGoldens,
//     already fixed under F-280).
//
// Returns the passed, skipped, and failed fixture names/details.
func scanFixtures(dirs []string, opts compiler.CompileOptions) (passed, skipped []string, failures []fixtureFailure) {
	for _, testDir := range dirs {
		name := filepath.Base(testDir)

		if !fixtureAllowlistedForGo(testDir) {
			skipped = append(skipped, name)
			continue
		}

		sourcePath := findGoSource(testDir)
		if sourcePath == "" {
			failures = append(failures, fixtureFailure{
				name:   name,
				kind:   "missing-source",
				actual: fmt.Sprintf("no .runar.go source found for fixture '%s'", name),
			})
			continue
		}

		// Step 1: source -> ANF IR
		program, err := compiler.CompileSourceToIR(sourcePath, opts)
		if err != nil {
			failures = append(failures, fixtureFailure{name: name, kind: "compile-ir", actual: err.Error()})
			continue
		}

		// Serialize ANF to JSON
		rawIR, err := json.MarshalIndent(program, "", "  ")
		if err != nil {
			failures = append(failures, fixtureFailure{name: name, kind: "serialize-ir", actual: err.Error()})
			continue
		}
		actualIR, err := canonicalizeJSON(rawIR)
		if err != nil {
			failures = append(failures, fixtureFailure{name: name, kind: "canonicalize-actual-ir", actual: err.Error()})
			continue
		}

		// Step 2: source -> script hex
		artifact, err := compiler.CompileFromSource(sourcePath, opts)
		if err != nil {
			failures = append(failures, fixtureFailure{name: name, kind: "compile-hex", actual: err.Error()})
			continue
		}
		actualHex := strings.ToLower(strings.Join(strings.Fields(artifact.Script), ""))

		// Step 3: compare against goldens
		if fail := compareGoldens(name, testDir, actualIR, actualHex); fail != nil {
			failures = append(failures, *fail)
			continue
		}

		passed = append(passed, name)
	}
	return passed, skipped, failures
}

func shortDiff(expected, actual string) string {
	expLines := strings.Split(expected, "\n")
	actLines := strings.Split(actual, "\n")
	max := len(expLines)
	if len(actLines) > max {
		max = len(actLines)
	}
	var sb strings.Builder
	shown := 0
	for i := 0; i < max; i++ {
		var e, a string
		if i < len(expLines) {
			e = expLines[i]
		} else {
			e = "<EOF>"
		}
		if i < len(actLines) {
			a = actLines[i]
		} else {
			a = "<EOF>"
		}
		if e != a {
			sb.WriteString(fmt.Sprintf("    line %d:\n      - expected: %s\n      + actual:   %s\n", i+1, e, a))
			shown++
			if shown >= 12 {
				sb.WriteString("    ... (truncated)\n")
				break
			}
		}
	}
	if sb.Len() == 0 {
		sb.WriteString("    (strings differ but no line diff; likely trailing whitespace)\n")
	}
	return sb.String()
}

// compareGoldens checks a single fixture's actual ANF IR / script hex
// against its checked-in `expected-ir.json` / `expected-script.hex`.
//
// A missing or unreadable golden file is a failure (fixtureFailure with
// kind "read-golden-ir" / "read-golden-hex"), never a silent pass: every
// fixture under conformance/tests ships both goldens, so there is no
// legitimate "golden intentionally absent" case for this sweep to tolerate.
// Returns nil when both goldens are present, readable, and byte-identical
// to the actual output.
func compareGoldens(name, testDir, actualIR, actualHex string) *fixtureFailure {
	expectedIRPath := filepath.Join(testDir, "expected-ir.json")
	raw, err := os.ReadFile(expectedIRPath)
	if err != nil {
		return &fixtureFailure{name: name, kind: "read-golden-ir", actual: err.Error()}
	}
	expectedIR, err := canonicalizeJSON(raw)
	if err != nil {
		return &fixtureFailure{name: name, kind: "canonicalize-golden-ir", actual: err.Error()}
	}
	if actualIR != expectedIR {
		return &fixtureFailure{name: name, kind: "ir-mismatch", expected: expectedIR, actual: actualIR}
	}

	expectedHexPath := filepath.Join(testDir, "expected-script.hex")
	rawHex, err := os.ReadFile(expectedHexPath)
	if err != nil {
		return &fixtureFailure{name: name, kind: "read-golden-hex", actual: err.Error()}
	}
	expectedHex := strings.ToLower(strings.Join(strings.Fields(string(rawHex)), ""))
	if actualHex != expectedHex {
		return &fixtureFailure{name: name, kind: "script-mismatch", expected: expectedHex, actual: actualHex}
	}

	return nil
}

// TestCompareGoldens_MissingGoldenIsFailureNotSkip proves that compareGoldens
// treats a missing/unreadable expected-ir.json or expected-script.hex as a
// failure, not as "nothing to compare, mark it passed". This is the
// regression guard for F-280: the inline version of this logic used to gate
// each comparison behind `if _, err := os.Stat(path); err == nil { ... }`,
// so an unreadable golden skipped the comparison entirely and the fixture
// fell through to `passed` with zero bytes actually checked.
//
// It does NOT prove TestConformanceGoldens itself wires compareGoldens in
// (that's asserted by TestConformanceGoldens passing after the refactor);
// it proves the helper's missing-golden contract in isolation.
func TestCompareGoldens_MissingGoldenIsFailureNotSkip(t *testing.T) {
	t.Run("missing expected-ir.json", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "expected-script.hex"), []byte("deadbeef"), 0o644); err != nil {
			t.Fatalf("write expected-script.hex: %v", err)
		}
		// expected-ir.json deliberately absent.
		got := compareGoldens("fake-fixture", dir, `{"anything":true}`, "deadbeef")
		if got == nil {
			t.Fatalf("compareGoldens returned nil (treated missing expected-ir.json as a pass); want a failure with kind=read-golden-ir")
		}
		if got.kind != "read-golden-ir" {
			t.Errorf("got failure kind %q, want %q", got.kind, "read-golden-ir")
		}
	})

	t.Run("missing expected-script.hex", func(t *testing.T) {
		dir := t.TempDir()
		irJSON := `{"anything":true}`
		if err := os.WriteFile(filepath.Join(dir, "expected-ir.json"), []byte(irJSON), 0o644); err != nil {
			t.Fatalf("write expected-ir.json: %v", err)
		}
		// Make the "actual" IR match the golden exactly (after canonicalization)
		// so the IR comparison passes and the test isolates the missing-hex path.
		canonicalIR, err := canonicalizeJSON([]byte(irJSON))
		if err != nil {
			t.Fatalf("canonicalizeJSON: %v", err)
		}
		// expected-script.hex deliberately absent.
		got := compareGoldens("fake-fixture", dir, canonicalIR, "deadbeef")
		if got == nil {
			t.Fatalf("compareGoldens returned nil (treated missing expected-script.hex as a pass); want a failure with kind=read-golden-hex")
		}
		if got.kind != "read-golden-hex" {
			t.Errorf("got failure kind %q, want %q", got.kind, "read-golden-hex")
		}
	})
}

func TestConformanceGoldens(t *testing.T) {
	// Resolve conformance/tests relative to this test file. `go test` runs
	// with CWD = package directory, which is compilers/go.
	conformanceDir := filepath.Clean(filepath.Join("..", "..", "conformance", "tests"))
	entries, err := os.ReadDir(conformanceDir)
	if err != nil {
		t.Fatalf("readdir %s: %v", conformanceDir, err)
	}

	dirs := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(conformanceDir, e.Name()))
		}
	}
	sort.Strings(dirs)

	opts := compiler.CompileOptions{DisableConstantFolding: true}

	passed, skipped, failures := scanFixtures(dirs, opts)

	total := len(dirs)
	t.Logf(
		"\n=== Go conformance-goldens summary: %d pass / %d fail / %d skipped (compilers allowlist excludes go) (of %d fixtures) ===",
		len(passed), len(failures), len(skipped), total,
	)
	if len(skipped) > 0 {
		t.Log("Skipped (source.json \"compilers\" allowlist excludes go):")
		for _, n := range skipped {
			t.Logf("  - %s", n)
		}
	}

	for i, fail := range failures {
		if i >= 5 {
			break
		}
		switch fail.kind {
		case "ir-mismatch":
			t.Logf("\n--- FAIL: %s (ir-mismatch) ---", fail.name)
			t.Logf("  expected %d chars, actual %d chars:", len(fail.expected), len(fail.actual))
			t.Logf("%s", shortDiff(fail.expected, fail.actual))
		case "script-mismatch":
			minLen := len(fail.expected)
			if len(fail.actual) < minLen {
				minLen = len(fail.actual)
			}
			firstDiff := minLen
			for i := 0; i < minLen; i++ {
				if fail.expected[i] != fail.actual[i] {
					firstDiff = i
					break
				}
			}
			lo := firstDiff - 20
			if lo < 0 {
				lo = 0
			}
			expHi := firstDiff + 20
			if expHi > len(fail.expected) {
				expHi = len(fail.expected)
			}
			actHi := firstDiff + 20
			if actHi > len(fail.actual) {
				actHi = len(fail.actual)
			}
			t.Logf("\n--- FAIL: %s (script-mismatch) ---", fail.name)
			t.Logf("  expected %d hex chars, actual %d hex chars", len(fail.expected), len(fail.actual))
			t.Logf("  first diff at hex offset %d (byte %d)", firstDiff, firstDiff/2)
			t.Logf("  expected: ...%s...", fail.expected[lo:expHi])
			t.Logf("  actual:   ...%s...", fail.actual[lo:actHi])
		default:
			t.Logf("\n--- FAIL: %s (%s) ---\n  %s", fail.name, fail.kind, fail.actual)
		}
	}
	if len(failures) > 5 {
		t.Logf("\n... and %d more failures:", len(failures)-5)
		for _, fail := range failures[5:] {
			t.Logf("  - %s", fail.name)
		}
	}

	if len(failures) > 0 {
		t.Fatalf("%d of %d fixtures failed conformance-goldens", len(failures), total)
	}
}

// N-124: the Go golden harness had the same "missing-source collected but
// never asserted" defect that F-151 (Ruby), F-285 (Rust) and F-323 (Python)
// fixed in their own harnesses: a fixture whose `.runar.go` source could not
// be resolved was appended only to the `missing` slice printed in the
// summary, never to `failures`, so TestConformanceGoldens's final
// `t.Fatalf(len(failures) > 0, ...)` never consulted it -- "every fixture's
// .runar.go entry repointed at a nonexistent file" reported "0 fail".
// scanFixtures is extracted so this is directly testable against synthetic,
// throwaway fixture directories (via t.TempDir()), without depending on or
// risking the real conformance corpus.
//
// What this proves: scanFixtures classifies a fixture with no resolvable
// .runar.go source as a FAILURE (kind "missing-source"), not as a silently
// unasserted bucket.
//
// What this does not prove: that the real conformance/tests corpus is free
// of the gap today (it is -- every fixture ships a .runar.go source); nor
// does it prove TestConformanceGoldens itself wires scanFixtures's return
// value into t.Fatalf correctly end-to-end -- that is covered by
// TestConformanceGoldens passing against the real corpus above.
func TestScanFixtures_MissingSourceIsFailureNotSilent(t *testing.T) {
	dir := t.TempDir()
	// No source.json, no *.runar.go file anywhere in the scratch dir.

	_, _, failures := scanFixtures([]string{dir}, compiler.CompileOptions{DisableConstantFolding: true})

	name := filepath.Base(dir)
	var found *fixtureFailure
	for i := range failures {
		if failures[i].name == name {
			found = &failures[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("scanFixtures did not report a failure for a fixture with no .runar.go source (got failures=%v)", failures)
	}
	if found.kind != "missing-source" {
		t.Errorf("got failure kind %q, want %q", found.kind, "missing-source")
	}
}

// N-124: scanFixtures must SKIP (not fail) a fixture whose source.json
// `compilers` allowlist excludes "go" -- mirroring the Rust harness's
// fixture_allowlisted_for_rust (F-285) and the Ruby harness's
// read_compiler_allowlist (F-151). Without this, treating every
// missing-source fixture as a failure (the fix above) would wrongly fail a
// fixture that legitimately ships no .runar.go source because Go is not a
// required conformance target for it.
//
// What this proves: fixtureAllowlistedForGo / scanFixtures correctly skip
// (rather than fail) an allowlist-excluded fixture with no .runar.go source.
//
// What this does not prove: that the real conformance corpus contains such
// a fixture today for Go specifically -- it does not; the four existing
// "compilers": ["go"] fixtures all include go, never exclude it. This is a
// synthetic, throwaway fixture directory.
func TestScanFixtures_SkipsAllowlistExcludedFixtureWithNoSource(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "source.json"), []byte(`{"compilers":["java"]}`), 0o644); err != nil {
		t.Fatalf("write source.json: %v", err)
	}
	// No *.runar.go file -- legitimate, since the allowlist excludes go.

	_, skipped, failures := scanFixtures([]string{dir}, compiler.CompileOptions{DisableConstantFolding: true})

	name := filepath.Base(dir)
	for _, f := range failures {
		if f.name == name {
			t.Fatalf("an allowlist-excluded fixture must not be reported as a failure (got: %v)", f)
		}
	}
	found := false
	for _, s := range skipped {
		if s == name {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in skipped, got skipped=%v", name, skipped)
	}
}
