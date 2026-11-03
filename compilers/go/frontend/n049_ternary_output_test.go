package frontend

import (
	"fmt"
	"strings"
	"testing"
)

// N-049 (EXT-2 "TernaryToll") — an output intrinsic inside a ternary arm.
//
// lowerTernaryExpr lowers each arm into ctx.subContext(); an addOutput /
// addRawOutput / addDataOutput in an arm registers its ref there, and the arm
// context is dropped, so the ref never reaches the method's output list — the
// only input to the auto-injected continuation hash. Measured on every tier:
// the payee output could be dropped by the spender and the honest spend was
// rejected. Fail-closed like R-127: the validator refuses an output intrinsic
// (direct, or via an inlined private helper) in either arm with the shared
// N-049 diagnostic, and pass 4 refuses it again when reached without
// validation. A ternary that only selects VALUES stays accepted.
//
// What this proves: the Go tier refuses the ternary-arm shapes at pass 2 and
// pass 4 with the shared diagnostic and still lowers the value-selecting
// control. What it does not prove: anything about emitted bytes (the
// cross-tier control is conformance/negatives/ternary-output-control.test.ts).

const n049Head = `
class ConditionalPayout extends StatefulSmartContract {
  count: bigint;
  readonly payee: ByteString;
  readonly refund: ByteString;

  constructor(count: bigint, payee: ByteString, refund: ByteString) {
    super(count, payee, refund);
    this.count = count;
    this.payee = payee;
    this.refund = refund;
  }
`

const n049TernaryArms = n049Head + `
  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.addRawOutput(50000n, this.payee)
                    : this.addRawOutput(50000n, this.refund);
  }
}
`

const n049ViaHelper = n049Head + `
  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.payTo(this.payee) : this.payTo(this.refund);
  }

  private payTo(script: ByteString): void {
    this.addRawOutput(50000n, script);
  }
}
`

const n049ValueSelectingControl = n049Head + `
  public release() {
    this.addOutput(1000n, this.count);
    this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
  }
}
`

const n049Refusal = "Output intrinsic 'addRawOutput' cannot be called inside a conditional (ternary) expression arm."

func n049ValidationErrors(t *testing.T, source string) string {
	t.Helper()
	result := ParseSource([]byte(source), "ConditionalPayout.runar.ts")
	if len(result.Errors) > 0 || result.Contract == nil {
		t.Fatalf("parse: %v", result.ErrorStrings())
	}
	var msgs []string
	for _, d := range Validate(result.Contract).Errors {
		msgs = append(msgs, d.Message)
	}
	return strings.Join(msgs, "\n")
}

func TestN049ValidatorRefusesOutputIntrinsicInTernaryArm(t *testing.T) {
	if got := n049ValidationErrors(t, n049TernaryArms); !strings.Contains(got, n049Refusal) {
		t.Fatalf("validator did not refuse addRawOutput in a ternary arm with the N-049 diagnostic; got: %q", got)
	}
}

func TestN049ValidatorRefusesOutputReachedThroughHelperInTernaryArm(t *testing.T) {
	want := "Output intrinsic 'addRawOutput' (reached through private method 'payTo') cannot be called inside a conditional (ternary) expression arm."
	if got := n049ValidationErrors(t, n049ViaHelper); !strings.Contains(got, want) {
		t.Fatalf("validator did not refuse a helper-emitted output in a ternary arm; got: %q", got)
	}
}

func TestN049LoweringRefusesTernaryArmOutputWithoutValidation(t *testing.T) {
	result := ParseSource([]byte(n049TernaryArms), "ConditionalPayout.runar.ts")
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
	if !strings.Contains(refusal, n049Refusal) {
		t.Fatalf("ANF lowering did not refuse an output intrinsic in a ternary arm with the N-049 diagnostic; got: %q", refusal)
	}
}

func TestN049ValueSelectingTernaryStillAccepted(t *testing.T) {
	if got := n049ValidationErrors(t, n049ValueSelectingControl); got != "" {
		t.Fatalf("validator refused a value-selecting ternary: %s", got)
	}
	if _, refusal := lowerOrRefuse(t, n049ValueSelectingControl); refusal != "" {
		t.Fatalf("lowering refused a value-selecting ternary: %s", refusal)
	}
}
