package compiler

// F-179 — with IncludeSourceMap, opcodes produced by the peephole optimizer
// and the OP_IF of an `if` rebuilt by optimizeNestedIf must still be mapped
// back to the source statement they came from.
//
// Before the fix, PUSH(1) + OP_ADD of `x + 1n` was fused into an OP_1ADD with
// no SourceLoc, and optimizeNestedIf rebuilt the `if` op without its
// SourceLoc, so the emitted source map had no entry for either opcode.
//
// What this proves: end to end through CompileFromSourceStrWithResult, the
// fused OP_1ADD maps to the `const y = x + 1n` line and the OP_IF maps to the
// `if (mode)` line.
//
// What this does not prove: column accuracy beyond the statement start (the
// conformance/source-map independent oracle covers that), or anything about
// the other tiers. It equates ASM token index with opcodeIndex, which only
// holds for a script without raw_bytes spans or multi-token pushes — true for
// this contract.

import (
	"strings"
	"testing"
)

const f179Source = `import { SmartContract, assert } from 'runar-lang';

export class F179 extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public check(x: bigint, mode: boolean) {
    const y = x + 1n;
    if (mode) {
      assert(y > this.t);
    } else {
      assert(y < this.t);
    }
  }
}
`

func TestF179_SourceMap_MapsFused1AddAndRebuiltIf(t *testing.T) {
	result := CompileFromSourceStrWithResult(f179Source, "F179.runar.ts",
		CompileOptions{IncludeSourceMap: true})
	if !result.Success {
		t.Fatalf("compile failed: %v", result.Diagnostics)
	}
	if result.Artifact.SourceMapData == nil {
		t.Fatalf("no source map in artifact")
	}
	lineOf := func(needle string) int {
		for i, l := range strings.Split(f179Source, "\n") {
			if strings.Contains(l, needle) {
				return i + 1
			}
		}
		t.Fatalf("needle %q not in source", needle)
		return 0
	}
	asm := strings.Fields(result.ScriptAsm)
	indexOf := func(code string) int {
		for i, tok := range asm {
			if tok == code {
				return i
			}
		}
		t.Fatalf("%s not in asm: %s", code, result.ScriptAsm)
		return -1
	}
	mappings := result.Artifact.SourceMapData.Mappings
	lineAt := func(idx int) int {
		for _, m := range mappings {
			if m.OpcodeIndex == idx {
				return m.Line
			}
		}
		return -1
	}

	cases := []struct {
		code, needle string
	}{
		{"OP_1ADD", "const y = x + 1n"},
		{"OP_IF", "if (mode)"},
	}
	for _, c := range cases {
		idx := indexOf(c.code)
		want := lineOf(c.needle)
		if got := lineAt(idx); got != want {
			t.Errorf("%s at opcodeIndex %d mapped to line %d, want line %d (%q); asm=%s mappings=%+v",
				c.code, idx, got, want, c.needle, result.ScriptAsm, mappings)
		}
	}
}
