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

	var passed []string
	var missing []string
	var failures []fixtureFailure

	opts := compiler.CompileOptions{DisableConstantFolding: true}

	for _, testDir := range dirs {
		name := filepath.Base(testDir)
		sourcePath := findGoSource(testDir)
		if sourcePath == "" {
			missing = append(missing, name)
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
		expectedIRPath := filepath.Join(testDir, "expected-ir.json")
		if _, err := os.Stat(expectedIRPath); err == nil {
			raw, err := os.ReadFile(expectedIRPath)
			if err != nil {
				failures = append(failures, fixtureFailure{name: name, kind: "read-golden-ir", actual: err.Error()})
				continue
			}
			expectedIR, err := canonicalizeJSON(raw)
			if err != nil {
				failures = append(failures, fixtureFailure{name: name, kind: "canonicalize-golden-ir", actual: err.Error()})
				continue
			}
			if actualIR != expectedIR {
				failures = append(failures, fixtureFailure{
					name:     name,
					kind:     "ir-mismatch",
					expected: expectedIR,
					actual:   actualIR,
				})
				continue
			}
		}

		expectedHexPath := filepath.Join(testDir, "expected-script.hex")
		if _, err := os.Stat(expectedHexPath); err == nil {
			raw, err := os.ReadFile(expectedHexPath)
			if err != nil {
				failures = append(failures, fixtureFailure{name: name, kind: "read-golden-hex", actual: err.Error()})
				continue
			}
			expectedHex := strings.ToLower(strings.Join(strings.Fields(string(raw)), ""))
			if actualHex != expectedHex {
				failures = append(failures, fixtureFailure{
					name:     name,
					kind:     "script-mismatch",
					expected: expectedHex,
					actual:   actualHex,
				})
				continue
			}
		}

		passed = append(passed, name)
	}

	total := len(dirs)
	t.Logf(
		"\n=== Go conformance-goldens summary: %d pass / %d fail / %d missing-source (of %d fixtures) ===",
		len(passed), len(failures), len(missing), total,
	)
	if len(missing) > 0 {
		t.Log("Missing .runar.go source files:")
		for _, n := range missing {
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
