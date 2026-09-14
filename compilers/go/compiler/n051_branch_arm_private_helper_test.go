package compiler

// Port of the TypeScript reference test
// packages/runar-compiler/src/__tests__/n051-branch-arm-private-helper.test.ts.
//
// N-051 — a private-helper call inside a BRANCH ARM must inline the callee.
//
// spec/semantics.md §6.3 defines a private method as source-level substitution
// at every call site, and its canonical example is a helper call in EXPRESSION
// position:
//
//	private square(x: bigint): bigint { return x * x; }
//	public verify(n: bigint): void { assert(this.square(n) < 100n); }
//	// After inlining:
//	public verify(n: bigint): void { assert(n * n < 100n); }
//
// spec/ir-format.md §4.7 keeps `method_call` in the canonical ANF ("Inlining
// happens in a later compiler phase"), so the substitution is stack lowering's
// job — and stack lowering lowers an `if`'s arms in a FRESH context.
//
// The defect: codegen/stack.go's lowerIf built thenCtx / elseCtx with
// newLoweringContext, which initialises privateMethods to an EMPTY map, and
// never copied ctx.privateMethods into them. Inside an arm the callee was
// therefore unknown, lowerMethodCall fell through to lowerCall, and the call
// lowered to a bare push. Go ACCEPTED and emitted a script that never evaluates
// the helper — OP_0 where the source says OP_1ADD:
//
//	const v: bigint = p > 0n ? this.bump(p) : 0n;   // bump(x) = x + 1n
//
//	ts / zig / ruby / java   7600a0638b6700776800a2         (correct)
//	go                       7600a063006700776800a2         (silently wrong)
//	python                   7600a063007c00776700776800a2   (silently wrong)
//	rust                     rejected: "unknown function 'bump'"
//
// That is the fund-safety half: the covenant deploys, and the arm computes a
// value the contract never asked for.
//
// The tier-independent proof, and the second test below: changing the callee
// body from `x + 1n` to `x + 2n` changed NOTHING in Go's output. A compiler
// that emits identical bytes for two different programs is not merely
// disagreeing with its peers.
//
// This is the branch-lowering arm contract (NEW-014 / NEW-018) again: an arm
// context is constructed fresh, so every field it needs has to be re-plumbed by
// hand. scriptLevelCodeSeparator was re-plumbed by R-010 and renamedParams by
// issue #130 — both with a comment at the copy site. privateMethods was missed.
// TS, Ruby and Java already copied it, which is exactly why those tiers were
// correct.
//
// The hexes are the SEVEN-TIER agreed output. Every tier pins the same strings,
// which is what makes this a parity gate: a tier that lowers the fix
// differently fails its own test.

import "testing"

const n051Prelude = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }
`

// Helper called from a ternary arm.
const n051TernaryArmPlus1 = n051Prelude + `  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    const v: bigint = p > 0n ? this.bump(p) : 0n;
    assert(v >= this.s);
  }
}
`

// Same shape, different callee body — the body-independence probe.
const n051TernaryArmPlus2 = n051Prelude + `  private bump(x: bigint): bigint { return x + 2n; }

  public m(p: bigint): void {
    const v: bigint = p > 0n ? this.bump(p) : 0n;
    assert(v >= this.s);
  }
}
`

// Control: the same program with the helper inlined by hand.
const n051TernaryArmManualInline = n051Prelude + `  public m(p: bigint): void {
    const v: bigint = p > 0n ? p + 1n : 0n;
    assert(v >= this.s);
  }
}
`

// Helper called from an `if` STATEMENT arm.
const n051IfStatementArm = n051Prelude + `  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    let v: bigint = 0n;
    if (p > 0n) {
      v = this.bump(p);
    } else {
      v = 0n;
    }
    assert(v >= this.s);
  }
}
`

// Control: the same `if` with no helper call in either arm.
const n051IfStatementArmNoHelper = n051Prelude + `  public m(p: bigint): void {
    let v: bigint = 0n;
    if (p > 0n) {
      v = p + 1n;
    } else {
      v = 0n;
    }
    assert(v >= this.s);
  }
}
`

// Control: a helper call in ordinary statement position, outside any arm.
const n051StatementPosition = n051Prelude + `  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    const v: bigint = this.bump(p);
    assert(v >= this.s);
  }
}
`

func TestN051BranchArmPrivateHelper_SevenTierScript(t *testing.T) {
	cases := []struct {
		label  string
		source string
		want   string
	}{
		{"ternary-arm/+1", n051TernaryArmPlus1, "7600a0638b6700776800a2"},
		{"ternary-arm/+2", n051TernaryArmPlus2, "7600a06352936700776800a2"},
		{"ternary-arm-manual-inline", n051TernaryArmManualInline, "7600a0638b6700776800a2"},
		{"if-statement-arm", n051IfStatementArm, "007800a0637c8b767676537a757777670076537a757768517a7500a2"},
		{"if-statement-arm-no-helper", n051IfStatementArmNoHelper, "007800a0637c8b7677670076537a757768517a7500a2"},
		{"statement-position", n051StatementPosition, "8b00a2"},
	}

	for _, tc := range cases {
		for _, disable := range []bool{true, false} {
			mode := "fold-on"
			if disable {
				mode = "fold-off"
			}
			t.Run(tc.label+"/"+mode, func(t *testing.T) {
				got := compileScriptHex(t, tc.source, disable)
				if got != tc.want {
					t.Fatalf("script hex diverged from the seven-tier agreed output\n got: %s\nwant: %s", got, tc.want)
				}
			})
		}
	}
}

// spec/semantics.md §6.3: inlining IS substitution, so a helper call in a
// ternary arm and the hand-substituted program are the same program.
func TestN051TernaryArmMatchesManualInline(t *testing.T) {
	for _, disable := range []bool{true, false} {
		withHelper := compileScriptHex(t, n051TernaryArmPlus1, disable)
		manual := compileScriptHex(t, n051TernaryArmManualInline, disable)
		if withHelper != manual {
			t.Fatalf("helper-in-arm and hand-inlined source differ (disableConstantFolding=%v)\n helper: %s\n manual: %s",
				disable, withHelper, manual)
		}
	}
}

// The tier-independent oracle. No reference tier is consulted: a compiler that
// emits the same bytes for `x + 1n` and `x + 2n` has dropped the callee body,
// whatever its peers do.
func TestN051CalleeBodyReachesTheArm(t *testing.T) {
	for _, disable := range []bool{true, false} {
		plus1 := compileScriptHex(t, n051TernaryArmPlus1, disable)
		plus2 := compileScriptHex(t, n051TernaryArmPlus2, disable)
		if plus1 == plus2 {
			t.Fatalf("two different helper bodies compiled to the same script (disableConstantFolding=%v): %s",
				disable, plus1)
		}
	}
}
