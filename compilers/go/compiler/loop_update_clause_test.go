// R-065 regression guard for the Go tier: the for-loop `update` clause is
// parsed, carried through the whole AST, and then never validated and never
// lowered.
//
// `frontend/anf_lower.go`'s `extractLoopStep` only ever understood a UNIT
// step: it returns `1` for `IncrementExpr`, `-1` for `DecrementExpr`, and
// otherwise falls back to the *comparison direction* — so any other update
// clause is silently coerced to `±1` and the clause itself is discarded.
// `validator.go`'s `validateForStatement` never looked at `stmt.Update` at
// all, and `typecheck.go`'s `ForStmt` arm checked `Init`, `Condition` and
// `Body` but skipped `Update` entirely.
//
// Three shapes of the same hole, all observable from ordinary source:
//
//   - `for (let i = 0n; i < 3n; undefinedFn())` compiled to byte-identical
//     output. A nonexistent function name raised nothing — a hole in the rule
//     that only Rúnar builtins and contract methods are callable (CLAUDE.md
//     names `console.log` explicitly).
//   - `for (let i = 0n; i < 3n; this.count++)` silently DROPPED the state
//     write from the emitted script.
//   - a non-unit step (`i += 2` in the Go / Zig / Solidity surface formats)
//     unrolled 5 times over i = 0..4 instead of 3 times over i = 0,2,4.
//     Byte-identical to the `i++` loop, with no diagnostic. This tier was the
//     only one of the seven that accepted `i += 2n` written directly in the
//     `.runar.ts` surface — the other six rejected it in the parser.
//
// `spec/grammar.md` is authoritative and permits only the unit forms:
//
//	ForStatement
//	    = 'for' '(' 'let' Identifier ':' 'bigint' '=' Expression ';'
//	                Identifier RelOp Expression ';'
//	                Identifier ( '++' | '--' ) ')' Block
//
// and, under Statement Restrictions, "The loop variable MUST use simple
// increment (`++`) or decrement (`--`)". So rejecting is the fix rather than
// lowering: the ANF `loop` node can express exactly
// `{count, iterVar, start, step, body}` and synthesizes the iterator on
// unrolled iteration k as `start + k*step`. There is no slot for an arbitrary
// update statement, and appending the update's lowering to the loop body would
// re-emit `i++` as a dead binding on every loop that already compiles
// correctly — moving bytes across the whole corpus to express nothing.
//
// The diagnostic text is shared verbatim with the other six tiers.
//
// What these tests do NOT prove: nothing here says the update clause is
// *lowered*; the contract is that a non-representable update is a compile
// error instead of silent output. The controls pin the `bounded-loop` shape
// only — they show the fix refuses nothing that compiled before, not that
// every loop in the corpus is unaffected (the conformance goldens cover that).
package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The one correct answer. `bounded-loop` sums `start + i` for i in 0..4 and
// asserts the total; all nine frontends lower to these exact 42 bytes.
const boundedLoopHex = "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c"

const loopUpdateDiagnostic = "must advance the loop variable by one"

func readExample(t *testing.T, rel string) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", rel)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("failed to read %s: %v", p, err)
	}
	return string(data)
}

// compileHex runs the full source pipeline and returns the script hex, or the
// joined diagnostics when the compile fails.
func compileHex(source, fileName string) (hex string, diags string, ok bool) {
	res := CompileFromSourceStrWithResult(source, fileName)
	var msgs []string
	for _, d := range res.Diagnostics {
		msgs = append(msgs, d.Message)
	}
	joined := strings.Join(msgs, "\n")
	if !res.Success || res.Artifact == nil {
		return "", joined, false
	}
	return res.Artifact.Script, joined, true
}

// tsWithUpdate is a stateful contract parameterised on the for-loop update
// clause.
func tsWithUpdate(update string) string {
	return fmt.Sprintf(`import { StatefulSmartContract, assert } from 'runar-lang';

class UpdateProbe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; %s) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
`, update)
}

// ---------------------------------------------------------------------------
// The defect
// ---------------------------------------------------------------------------

// The sharpest form for this tier: `i += 2n` written directly in the
// `.runar.ts` surface. Pre-fix this compiled to byte-identical output with the
// `i++` loop — five iterations over 0,1,2,3,4 where the source says three over
// 0,2,4.
func TestNonUnitStepIsRejectedNotCoerced_TS(t *testing.T) {
	hex, diags, ok := compileHex(tsWithUpdate("i += 2n"), "UpdateProbe.runar.ts")
	if ok {
		t.Fatalf("`i += 2n` must not compile: it silently unrolled with step 1 (%d hex chars)", len(hex))
	}
	if !strings.Contains(diags, loopUpdateDiagnostic) {
		t.Fatalf("rejection must carry the shared cross-tier diagnostic, got: %s", diags)
	}
}

// The same defect through the Zig surface, whose `while (c) : (i += 2)` fold
// produces the ASSIGNMENT spelling `i = i + 2` rather than a compound operator.
func TestNonUnitStepIsRejectedNotCoerced_Zig(t *testing.T) {
	source := strings.Replace(
		readExample(t, "examples/zig/bounded-loop/BoundedLoop.runar.zig"),
		"i += 1", "i += 2", 1)
	hex, diags, ok := compileHex(source, "BoundedLoop.runar.zig")
	if ok {
		t.Fatalf("`i += 2` must not compile through the Zig frontend (%d hex chars)", len(hex))
	}
	if !strings.Contains(diags, loopUpdateDiagnostic) {
		t.Fatalf("rejection must carry the shared cross-tier diagnostic, got: %s", diags)
	}
}

// The Go surface spelling of the same thing.
func TestNonUnitStepIsRejectedNotCoerced_Go(t *testing.T) {
	source := strings.Replace(
		readExample(t, "examples/go/bounded-loop/BoundedLoop.runar.go"),
		"i++", "i += 2", 1)
	hex, diags, ok := compileHex(source, "BoundedLoop.runar.go")
	if ok {
		t.Fatalf("`i += 2` must not compile through the Go frontend (%d hex chars)", len(hex))
	}
	if !strings.Contains(diags, loopUpdateDiagnostic) {
		t.Fatalf("rejection must carry the shared cross-tier diagnostic, got: %s", diags)
	}
}

// A negative non-unit step: guards against an accepted-set that only checks
// counting up.
func TestNegativeNonUnitStepIsRejected(t *testing.T) {
	source := readExample(t, "examples/zig/bounded-loop/BoundedLoop.runar.zig")
	source = strings.Replace(source, "var i: i64 = 0;", "var i: i64 = 5;", 1)
	source = strings.Replace(source, "while (i < 5) : (i += 1)", "while (i > 0) : (i -= 2)", 1)
	_, diags, ok := compileHex(source, "BoundedLoop.runar.zig")
	if ok {
		t.Fatal("`i -= 2` must not compile")
	}
	if !strings.Contains(diags, loopUpdateDiagnostic) {
		t.Fatalf("rejection must carry the shared cross-tier diagnostic, got: %s", diags)
	}
}

// CLAUDE.md: "the type checker rejects calls to unknown functions like
// Math.floor, console.log". It did — everywhere except the update clause.
func TestUndefinedFunctionInUpdateIsRejected(t *testing.T) {
	_, diags, ok := compileHex(tsWithUpdate("undefinedFn()"), "UpdateProbe.runar.ts")
	if ok {
		t.Fatal("a for-loop update calling an undefined function must not compile: " +
			"the type checker's unknown-function rule has to reach inside the update")
	}
	if strings.TrimSpace(diags) == "" {
		t.Fatal("rejection must carry a diagnostic, got an empty message")
	}
}

// The silent-drop half. `this.count++` in the update position is a write to
// contract state that never reached the emitted script.
func TestStateMutationInUpdateIsRejectedNotDropped(t *testing.T) {
	_, diags, ok := compileHex(tsWithUpdate("this.count++"), "UpdateProbe.runar.ts")
	if ok {
		t.Fatal("a state mutation in the update clause is not representable in the ANF " +
			"loop node, so it must be a compile error — silently dropping it is what " +
			"this test forbids")
	}
	if !strings.Contains(diags, loopUpdateDiagnostic) {
		t.Fatalf("rejection must carry the shared cross-tier diagnostic, got: %s", diags)
	}
}

// An update that advances a variable the loop model never binds.
func TestUpdateAdvancingAnotherVariableIsRejected(t *testing.T) {
	source := `import { SmartContract, assert } from 'runar-lang';

class OtherVar extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) { super(expected); this.expected = expected; }

  public verify(start: bigint): void {
    let sum: bigint = 0n;
    let j: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; j++) {
      sum = sum + start + i;
    }
    assert(sum === this.expected);
  }
}
`
	_, diags, ok := compileHex(source, "OtherVar.runar.ts")
	if ok {
		t.Fatal("`j++` advances a variable the loop model never binds")
	}
	if !strings.Contains(diags, loopUpdateDiagnostic) {
		t.Fatalf("rejection must carry the shared cross-tier diagnostic, got: %s", diags)
	}
}

// ---------------------------------------------------------------------------
// Controls: every shape that compiles today must still compile, byte-identical
// ---------------------------------------------------------------------------

func TestControlBoundedLoopBytesUnchanged(t *testing.T) {
	cases := []struct {
		name string
		rel  string
		file string
	}{
		{"ts i++", "examples/ts/bounded-loop/BoundedLoop.runar.ts", "BoundedLoop.runar.ts"},
		{"sol i++", "examples/sol/bounded-loop/BoundedLoop.runar.sol", "BoundedLoop.runar.sol"},
		{"go i++", "examples/go/bounded-loop/BoundedLoop.runar.go", "BoundedLoop.runar.go"},
		{"move while-fold", "examples/move/bounded-loop/BoundedLoop.runar.move", "BoundedLoop.runar.move"},
		{"python range()", "examples/python/bounded-loop/BoundedLoop.runar.py", "BoundedLoop.runar.py"},
		// `while (i < 5) : (i += 1)` — the assignment spelling `i = i + 1`,
		// which the accepted set has to keep alongside `i++`.
		{"zig i += 1", "examples/zig/bounded-loop/BoundedLoop.runar.zig", "BoundedLoop.runar.zig"},
		// `i = i.plus(Bigint.ONE)` — the Java surface's unit-step spelling.
		{"java i = i.plus(ONE)", "examples/java/src/main/java/runar/examples/bounded-loop/BoundedLoop.runar.java", "BoundedLoop.runar.java"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hex, diags, ok := compileHex(readExample(t, tc.rel), tc.file)
			if !ok {
				t.Fatalf("must still compile: %s", diags)
			}
			if hex != boundedLoopHex {
				t.Fatalf("lowering moved bytes:\n got %s\nwant %s", hex, boundedLoopHex)
			}
		})
	}
}

// A countdown loop: `i--` with `>`. Guards against an accepted set that only
// understands counting up.
func TestControlCountdownStillCompiles(t *testing.T) {
	source := `import { SmartContract, assert } from 'runar-lang';

class Countdown extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) { super(expected); this.expected = expected; }

  public verify(start: bigint): void {
    let sum: bigint = 0n;
    for (let i: bigint = 3n; i > 0n; i--) {
      sum = sum + start + i;
    }
    assert(sum === this.expected);
  }
}
`
	if _, diags, ok := compileHex(source, "Countdown.runar.ts"); !ok {
		t.Fatalf("a countdown loop must still compile: %s", diags)
	}
}
