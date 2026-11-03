package frontend

import (
	"fmt"
	"strings"
	"testing"
)

// F-009 / CL-BUG-187 — the .runar.ts surface parser must not map an
// unrecognised compound assignment to `+`.
//
// parseAugmentedAssignment switched on `+= -= *= /= %=` and fell through to
// `default: binOp = "+"`, so `a &= 3n` (and `|= ^= <<= >>= **=`) compiled to
// `a = a + 3n` with no diagnostic: the emitted script used OP_ADD.
//
// The TS reference (packages/runar-compiler/src/passes/01-parse.ts,
// parseExpressionStatement) defines the set: `+= -= *= /= %=` desugar to
// `a = a op b`; every other compound operator falls through to parseExpression
// and is refused with "Unsupported binary operator: '<op>'". Measured by
// running the TS compiler on each of the eleven operators. This test pins the
// Go tier to that exact set and diagnostic, in statement position and in a
// for-loop update clause (the second caller of parseAugmentedAssignment).
//
// Proves: the Go .runar.ts parser desugars exactly the five reference
// operators to the matching binary op, and refuses the six others with the
// reference diagnostic naming the operator, instead of emitting `+`.
// Does not prove: script behaviour (the out-of-band @bsv/sdk Spend.validate
// run in the F-009 remediation log covers that); other tiers' .runar.ts
// parsers; other surfaces' compound-assignment handling.

func f009Source(op string) string {
	return fmt.Sprintf(`
import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  constructor() { super(); }

  public unlock(x: bigint) {
    let a: bigint = x;
    a %s 3n;
    assert(a === 12n);
  }
}
`, op)
}

func TestF009_TSCompoundAssign_ReferenceOpsDesugar(t *testing.T) {
	cases := map[string]string{"+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%"}
	for op, want := range cases {
		t.Run(op, func(t *testing.T) {
			result := ParseSource([]byte(f009Source(op)), "C.runar.ts")
			if len(result.Errors) > 0 {
				t.Fatalf("%s: unexpected parse errors: %v", op, result.Errors)
			}
			body := methodBody(t, f009Source(op))
			assign, ok := body[1].(AssignmentStmt)
			if !ok {
				t.Fatalf("%s: expected AssignmentStmt, got %T", op, body[1])
			}
			bin, ok := assign.Value.(BinaryExpr)
			if !ok {
				t.Fatalf("%s: expected BinaryExpr value, got %T", op, assign.Value)
			}
			if bin.Op != want {
				t.Errorf("%s: desugared to %q, want %q", op, bin.Op, want)
			}
		})
	}
}

func TestF009_TSCompoundAssign_OtherOpsRefused(t *testing.T) {
	for _, op := range []string{"&=", "|=", "^=", "<<=", ">>=", "**="} {
		t.Run(op, func(t *testing.T) {
			result := ParseSource([]byte(f009Source(op)), "C.runar.ts")
			want := fmt.Sprintf("Unsupported binary operator: '%s'", op)
			found := false
			for _, e := range result.Errors {
				if strings.Contains(e.Message, want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s: expected parse error %q, got errors %v", op, want, result.Errors)
			}
		})
	}
}

func TestF009_TSCompoundAssign_ForUpdateRefused(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  constructor() { super(); }

  public unlock(x: bigint) {
    let s: bigint = x;
    for (let i: bigint = 1n; i < 8n; i <<= 1n) {
      s = s + i;
    }
    assert(s === 12n);
  }
}
`
	result := ParseSource([]byte(source), "C.runar.ts")
	want := "Unsupported binary operator: '<<='"
	for _, e := range result.Errors {
		if strings.Contains(e.Message, want) {
			return
		}
	}
	t.Fatalf("expected parse error %q for a for-update clause, got errors %v", want, result.Errors)
}
