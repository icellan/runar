package frontend

import (
	"strings"
	"testing"
)

// R-290 — `inlinePrivateMethodCall` used to emit a `load_const "@void"`
// sentinel when the inlined body produced no bindings.
//
// No tier's stack lowering recognises "@void" (unlike "@this", which IS
// special-cased), so the sentinel survived pass 4 and died in the hex decoder:
// Go said `invalid hex string: encoding/hex: invalid byte: U+0040 '@'`, Rust
// said `invalid hex string length: 5`. Neither names the method or the
// problem, and both fire only because the string happens to be odd-length and
// non-hex — an even-length sentinel would decode to zeros in Rust's
// `from_str_radix(..).unwrap_or(0)` and reach the script.
//
// It is reachable. `ComputeSideEffectSummary` resolves a called name through
// `privateByName`, a LAST-WINS map, and caches the result under that name; the
// lowerer's `getPrivateMethod` returns the FIRST match. Declare the public
// caller BEFORE two same-named privates and the two disagree: the summary
// describes the output-emitting `helper` (so `shouldInlinePrivate` is true)
// while the lowerer inlines the empty one. Measured pre-fix on the Go CLI:
// `--emit-ir` exited 0 with "@void" in the IR, `--hex` exited 1 with the
// hex-decoder message.
//
// Nothing in parse, validate or typecheck rejects the duplicate declaration —
// asserted below, so this test fails loudly rather than silently stopping
// testing pass 4 if that ever changes.
const r290EmptyInlinedBody = `
class R290Void extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(x: bigint) {
    this.count = x;
    this.helper();
  }

  private helper(): void {
  }

  private helper(): void {
    this.addOutput(1000n, this.count);
  }
}
`

// Control: the ordinary shape — one private helper that really does emit an
// output. The inlining path must still work; a refusal that simply rejected
// every inlined private would pass the test above.
const r290ControlEmittingHelper = `
class R290Control extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(x: bigint) {
    this.count = x;
    this.helper();
  }

  private helper(): void {
    this.addOutput(1000n, this.count);
  }
}
`

func TestR290EmptyInlinedBodyIsRefusedNotSentinelled(t *testing.T) {
	tcErrs, msg := r189Frontend(t, r290EmptyInlinedBody)
	if len(tcErrs) > 0 {
		t.Fatalf("passes 1-3 refused this contract, so pass 4 never saw it — the "+
			"test no longer covers the sentinel: %s", strings.Join(tcErrs, "; "))
	}
	if msg == "" {
		t.Fatal("the empty inlined body was accepted: ANF lowering produced a program")
	}
	want := "private method 'helper' was inlined but produced no bindings"
	if !strings.Contains(msg, want) {
		t.Fatalf("refusal does not name the method:\n  got:  %s\n  want: %s", msg, want)
	}
}

func TestR290NoVoidSentinelRemains(t *testing.T) {
	// A refusal that still emitted the sentinel first would satisfy the test
	// above on some other path. Nothing may carry "@void" any more.
	contract, _ := mustLowerToANF(t, r290ControlEmittingHelper)
	program := LowerToANF(contract)
	for _, m := range program.Methods {
		for _, b := range m.Body {
			if b.Value.ConstString != nil && *b.Value.ConstString == "@void" {
				t.Fatalf("method %q binding %q still carries the @void sentinel", m.Name, b.Name)
			}
		}
	}
}

func TestR290EmittingHelperStillInlines(t *testing.T) {
	tcErrs, msg := r189Frontend(t, r290ControlEmittingHelper)
	if len(tcErrs) > 0 {
		t.Fatalf("control must type-check: %s", strings.Join(tcErrs, "; "))
	}
	if msg != "" {
		t.Fatalf("control must still lower, got refusal: %s", msg)
	}
}
