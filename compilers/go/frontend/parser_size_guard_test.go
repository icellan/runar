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
