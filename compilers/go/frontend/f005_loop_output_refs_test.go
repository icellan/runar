package frontend

import (
	"fmt"
	"strings"
	"testing"
)

// F-005 / CL-BUG-186 — an output intrinsic inside a `for` body must never
// compile to a continuation that leaves its output out of hashOutputs.
//
// lowerForStatement lowers the body into bodyCtx := ctx.subContext(). Every
// addOutput / addRawOutput / addDataOutput in the body registers its ref on
// bodyCtx, and bodyCtx is dropped after the loop node is emitted, so those refs
// never reach methodCtx.addOutputRefs — the ONLY list the auto-injected
// continuation (hash256(cat(...)) === extractOutputHash(txPreimage)) is built
// from. The loop's outputs are computed and then not committed to.
//
// R-127's validator rule is supposed to keep every such contract out of pass 4,
// but it is a syntactic search and it does not look inside array literals: a
// loop body of `const xs = [this.addRawOutput(sats, script)];` passes parse,
// validate AND typecheck, and before this fix lowered to a continuation of
// cat(<top-level output>, <change>) — measured on the Go CLI. The same shape
// with the validator skipped (LowerToANF is exported) hits the same hole.
//
// Refusal, not merging: the loop is unrolled at stack-lowering time, so one
// body binding name denotes N physical slots and merging the refs by name would
// commit only the last iteration (see validateNoOutputIntrinsicInLoop). The
// lowering therefore refuses with R-127's shared diagnostic.
//
// What this proves: pass 4 itself will not emit a loop whose body registered an
// output ref, whatever let the contract through passes 1-3.
// What it does not prove: anything about the bytes on chain — the execution
// proof of the attack is
// packages/runar-testing/src/__tests__/f005-go-loop-output-continuation.test.ts,
// which runs the Go-compiled script on @bsv/sdk's Spend.

// The bypass: validate/typecheck accept it, and the loop's raw outputs used to
// be missing from the continuation hash.
const f005ArrayLiteralBypass = `
class F005Bypass extends StatefulSmartContract {
  count: bigint;
  readonly payScript: ByteString;

  constructor(count: bigint, payScript: ByteString) {
    super(count, payScript);
    this.count = count;
    this.payScript = payScript;
  }

  public pay(satsPerIter: bigint) {
    this.addOutput(1000n, this.count + 1n);
    for (let i = 0n; i < 2n; i++) {
      const xs = [this.addRawOutput(satsPerIter, this.payScript)];
    }
  }
}
`

// The brief's literal shape. The validator refuses it; lowering must refuse it
// too when reached without validation.
const f005DirectInLoop = `
class F005Direct extends StatefulSmartContract {
  count: bigint;
  readonly payScript: ByteString;

  constructor(count: bigint, payScript: ByteString) {
    super(count, payScript);
    this.count = count;
    this.payScript = payScript;
  }

  public pay(satsPerIter: bigint) {
    this.addOutput(1000n, this.count + 1n);
    for (let i = 0n; i < 2n; i++) {
      this.addRawOutput(satsPerIter, this.payScript);
    }
  }
}
`

// Control: a loop with no output intrinsic, next to top-level outputs. Must
// still lower, or a refusal that rejected every loop would pass the tests above.
const f005ControlLoopWithoutOutputs = `
class F005Control extends StatefulSmartContract {
  count: bigint;
  readonly payScript: ByteString;

  constructor(count: bigint, payScript: ByteString) {
    super(count, payScript);
    this.count = count;
    this.payScript = payScript;
  }

  public pay(satsPerIter: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + satsPerIter;
    }
    this.addOutput(1000n, this.count + acc);
    this.addRawOutput(satsPerIter, this.payScript);
  }
}
`

const f005Refusal = "cannot be called inside a loop body"

func TestF005LoweringRefusesLoopOutputThatEscapedTheValidator(t *testing.T) {
	// LowerToANF is exported; a caller that skips Validate must not get a
	// continuation that omits the loop's outputs, even if the validator didn't
	// catch the hidden output intrinsic inside the array literal.
	result := ParseSource([]byte(f005ArrayLiteralBypass), "F005Bypass.runar.ts")
	if len(result.Errors) > 0 || result.Contract == nil {
		t.Fatalf("parse: %v", result.ErrorStrings())
	}
	var refusal string
	func() {
		defer func() {
			if r := recover(); r != nil {
				refusal = fmt.Sprint(r)
			}
		}()
		LowerToANF(result.Contract)
	}()
	if refusal == "" {
		t.Fatal("ANF lowering accepted an addRawOutput inside a for body without validation; " +
			"its output is not in the continuation hash")
	}
	if !strings.Contains(refusal, f005Refusal) || !strings.Contains(refusal, "addRawOutput") {
		t.Fatalf("refused, but not with the R-127 diagnostic naming the intrinsic: %s", refusal)
	}
}

func TestF005LoweringRefusesLoopOutputWithoutValidation(t *testing.T) {
	// LowerToANF is exported; a caller that skips Validate must not get a
	// continuation that omits the loop's outputs.
	result := ParseSource([]byte(f005DirectInLoop), "F005Direct.runar.ts")
	if len(result.Errors) > 0 || result.Contract == nil {
		t.Fatalf("parse: %v", result.ErrorStrings())
	}
	var refusal string
	func() {
		defer func() {
			if r := recover(); r != nil {
				refusal = fmt.Sprint(r)
			}
		}()
		LowerToANF(result.Contract)
	}()
	if refusal == "" {
		t.Fatal("ANF lowering accepted an addRawOutput inside a for body without validation; " +
			"its output is not in the continuation hash")
	}
	if !strings.Contains(refusal, f005Refusal) || !strings.Contains(refusal, "addRawOutput") {
		t.Fatalf("refused, but not with the R-127 diagnostic naming the intrinsic: %s", refusal)
	}
}

func TestF005ControlLoopWithoutOutputsStillLowers(t *testing.T) {
	if _, refusal := lowerOrRefuse(t, f005ControlLoopWithoutOutputs); refusal != "" {
		t.Fatalf("a loop with no output intrinsic was refused: %s", refusal)
	}
}
