package frontend

import (
	"errors"
	"testing"
)

func TestParseSource_RejectsOversizedSource(t *testing.T) {
	// One byte over the cap. Content does not need to be valid Rúnar —
	// the size guard runs before tokenization.
	oversized := make([]byte, MaxSourceBytes+1)
	for i := range oversized {
		oversized[i] = ' '
	}

	res := ParseSource(oversized, "Counter.runar.ts")
	if res.SourceSizeErr == nil {
		t.Fatal("expected SourceSizeErr to be set, got nil")
	}
	if len(res.Errors) == 0 {
		t.Fatal("expected at least one diagnostic, got none")
	}
	var sse *SourceSizeExceededError
	if !errors.As(error(res.SourceSizeErr), &sse) {
		t.Fatalf("expected *SourceSizeExceededError, got %T", res.SourceSizeErr)
	}
	if sse.Limit != MaxSourceBytes {
		t.Errorf("expected Limit=%d, got %d", MaxSourceBytes, sse.Limit)
	}
	if sse.Actual != MaxSourceBytes+1 {
		t.Errorf("expected Actual=%d, got %d", MaxSourceBytes+1, sse.Actual)
	}
}

func TestParseSource_RejectsOversizedSourceRegardlessOfExtension(t *testing.T) {
	// The byte cap fires before extension dispatch.
	oversized := make([]byte, MaxSourceBytes+1)
	for i := range oversized {
		oversized[i] = ' '
	}

	for _, ext := range []string{".runar.ts", ".runar.sol", ".runar.move", ".runar.go", ".runar.py", ".runar.rs", ".runar.rb", ".runar.zig", ".runar.java"} {
		res := ParseSource(oversized, "Counter"+ext)
		if res.SourceSizeErr == nil {
			t.Errorf("ext %s: expected SourceSizeErr, got nil", ext)
		}
	}
}

func TestParseSource_AcceptsNormalSizedInput(t *testing.T) {
	// A minimal stateless contract well under the cap — the size guard
	// must NOT trip. (The full TS tree-sitter pipeline may still produce
	// diagnostics; we only assert SourceSizeErr is nil.)
	src := []byte(`class Counter extends SmartContract {
		public readonly x: bigint;
		constructor(x: bigint) { super(); this.x = x; }
		public unlock() {}
	}`)
	res := ParseSource(src, "Counter.runar.ts")
	if res.SourceSizeErr != nil {
		t.Fatalf("size guard incorrectly tripped: %v", res.SourceSizeErr)
	}
}

// F-177: the size guard is documented to cover ParseSource, Parse, and every
// per-format parser, but was only ever wired into ParseSource. A caller that
// imports this package and calls e.g. ParseJava or ParseGoContract directly
// (bypassing ParseSource) skipped the guard entirely and forced
// tokenization of arbitrarily large input. Each exported parser entry must
// refuse oversized input on its own, before touching the tokenizer, with the
// same *SourceSizeExceededError ParseSource already returns.
func TestExportedParsers_RejectOversizedSourceDirectly(t *testing.T) {
	oversized := make([]byte, MaxSourceBytes+1)
	for i := range oversized {
		oversized[i] = ' '
	}

	parsers := []struct {
		name string
		fn   func(source []byte, fileName string) *ParseResult
	}{
		{"Parse", Parse},
		{"ParseSolidity", ParseSolidity},
		{"ParseMove", ParseMove},
		{"ParseGoContract", ParseGoContract},
		{"ParsePython", ParsePython},
		{"ParseRustMacro", ParseRustMacro},
		{"ParseRuby", ParseRuby},
		{"ParseZig", ParseZig},
		{"ParseJava", ParseJava},
	}

	for _, p := range parsers {
		res := p.fn(oversized, "Counter.runar.ts")
		if res.SourceSizeErr == nil {
			t.Errorf("%s: expected SourceSizeErr to be set for %d-byte input (limit %d), got nil", p.name, len(oversized), MaxSourceBytes)
			continue
		}
		if res.SourceSizeErr.Limit != MaxSourceBytes {
			t.Errorf("%s: expected Limit=%d, got %d", p.name, MaxSourceBytes, res.SourceSizeErr.Limit)
		}
		if res.SourceSizeErr.Actual != MaxSourceBytes+1 {
			t.Errorf("%s: expected Actual=%d, got %d", p.name, MaxSourceBytes+1, res.SourceSizeErr.Actual)
		}
		if len(res.Errors) == 0 {
			t.Errorf("%s: expected at least one diagnostic, got none", p.name)
		}
	}
}

// Control for TestExportedParsers_RejectOversizedSourceDirectly: small input,
// well under the cap, must not trip the guard on any entry point (the guard
// itself only looks at byte length, so empty input is sufficient — each
// parser is still free to fail afterwards for its own syntactic reasons,
// which this test does not assert on).
func TestExportedParsers_AcceptSmallInputDirectly(t *testing.T) {
	small := []byte(``)

	parsers := []struct {
		name string
		fn   func(source []byte, fileName string) *ParseResult
	}{
		{"Parse", Parse},
		{"ParseSolidity", ParseSolidity},
		{"ParseMove", ParseMove},
		{"ParseGoContract", ParseGoContract},
		{"ParsePython", ParsePython},
		{"ParseRustMacro", ParseRustMacro},
		{"ParseRuby", ParseRuby},
		{"ParseZig", ParseZig},
		{"ParseJava", ParseJava},
	}

	for _, p := range parsers {
		res := p.fn(small, "Counter.runar.ts")
		if res.SourceSizeErr != nil {
			t.Errorf("%s: size guard incorrectly tripped on %d-byte input: %v", p.name, len(small), res.SourceSizeErr)
		}
	}
}
