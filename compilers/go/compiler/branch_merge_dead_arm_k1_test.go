package compiler

// Port of the TypeScript reference test
// packages/runar-compiler/src/__tests__/branch-merge-k1-and-dead-arm.test.ts.
//
// Three branch-merge defects fixed 2026-08-06, all reproducing in ALL SEVEN
// TIERS, all the PALMER-1 family ("one stack carrier asked to hold N live
// values") at the k=1 / k=2 arities the 2026-08-05 branch-merged-locals fix did
// not cover:
//
//	(1) FUND SAFETY, silent, fold-ON only. An `if` whose condition folds to a
//	    compile-time constant, whose STATICALLY DEAD arm rebinds exactly TWO
//	    locals both read after the branch, resolved every post-branch operand
//	    to the WRONG stack slot. Wrong in both directions: with s = -60267 the
//	    source REJECTS and the deployed script ACCEPTED (a covenant guard
//	    bypassed); with s = 1000 the source ACCEPTS and the deployed script
//	    REJECTED (an unspendable UTXO). Every tier emitted the same wrong
//	    script, so cross-tier agreement held perfectly while all seven were
//	    wrong together.
//	(2) A single local rebound FROM ITSELF in BOTH arms (`m0 = m0 + 1n` /
//	    `m0 = m0 - 1n`) was REJECTED with "value not found on stack", in both
//	    fold modes, though the same shape compiles at k=2 and without an else.
//	(3) The same k=1 merge under ANY compile-time-constant condition, fold-ON.
//
// Fixes: frontend/constant_fold.go no longer blanks a statically-dead arm (that
// erased the __merge$<i> result block both arms carry, so ONE stack slot was
// registered for K physical results), and codegen/stack.go's
// branchInPlaceRebindDepth adopts the slot both arms rebound in place at k=1.
//
// The hexes are the SEVEN-TIER agreed output. Every tier pins the same strings,
// which is what makes this a parity gate: a tier that lowers the fix
// differently fails its own test.

import (
	"strings"
	"testing"
)

// k=2 locals rebound by a STATICALLY DEAD arm, both read after the branch.
const deadArmK2Source = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }

  public m(p: bigint): void {
    let a: bigint = this.s;
    let b: bigint = -78n;
    if (false) {
      a = 1n;
      b = p;
    }
    assert(b <= a);
  }
}`

// One local rebound FROM ITSELF in both arms, read after the branch.
const selfReadBothArmsSource = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) { super(a); this.a = a; }

  public m(p: bigint): void {
    assert(this.a > -1000000n);
    let m0: bigint = 1n;
    if (p > 0n) {
      m0 = (m0 + 1n);
    } else {
      m0 = (m0 - 1n);
    }
    assert(m0 > -1000000n);
  }
}`

// The same k=1 merge under a compile-time-constant condition.
const constConditionK1Source = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) { super(a); this.a = a; }

  public m(p: bigint): void {
    assert(this.a > -1000000n);
    let m0: bigint = 1n;
    if (true) {
      m0 = 2n;
    } else {
      m0 = 3n;
    }
    assert(m0 > -1000000n);
  }
}`

func compileScriptHex(t *testing.T, source string, disableConstantFolding bool) string {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("compiler panicked instead of returning a result: %v", r)
		}
	}()

	result := CompileFromSourceStrWithResult(source, "C.runar.ts", CompileOptions{
		DisableConstantFolding: disableConstantFolding,
	})
	if !result.Success {
		var msgs []string
		for _, d := range result.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("compilation failed: %v", msgs)
	}
	return result.ScriptHex
}

func TestBranchMergeK1AndDeadArm_SevenTierScript(t *testing.T) {
	cases := []struct {
		label                  string
		source                 string
		disableConstantFolding bool
		want                   string
	}{
		{"dead-arm-k2/fold-on", deadArmK2Source, false,
			"00014e01ce006351547a6e7b757b7567527978557a7568527a75537a75527a7c7ba177"},
		{"dead-arm-k2/fold-off", deadArmK2Source, true,
			"00014e8f006351537a6e7b757b75676e547a7568527a75527a757ca1"},
		{"self-read-both-arms/fold-on", selfReadBothArmsSource, false,
			"000340420f0340428f7b7ca069517b00a06351787c9376776751787c94767768517a750340420f0340428f7b7ca07777"},
		{"self-read-both-arms/fold-off", selfReadBothArmsSource, true,
			"000340420f8fa069517c00a06351787c9376776751787c94767768517a750340420f8fa0"},
		{"const-condition-k1/fold-on", constConditionK1Source, false,
			"000340420f0340428f7b7ca0695151635276776753767768517a750340420f0340428f7b7ca0777777"},
		{"const-condition-k1/fold-off", constConditionK1Source, true,
			"000340420f8fa0695151635276776753767768517a750340420f8fa077"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := compileScriptHex(t, tc.source, tc.disableConstantFolding)
			if got != tc.want {
				t.Fatalf("script hex diverged from the seven-tier agreed output\n want %s\n  got %s", tc.want, got)
			}
		})
	}
}

// A constant condition must not be treated differently from a runtime one, at
// any arity. Before the fix, only the k=2 dead-arm form broke, and only under
// folding — which is why the fold-OFF parity fuzzers were blind to it.
func TestBranchMergeK1AndDeadArm_ConstAndRuntimeConditionsAgree(t *testing.T) {
	for _, cond := range []string{"if (false) {", "if (true) {", "if (p > 0n) {"} {
		for _, disable := range []bool{false, true} {
			source := strings.Replace(deadArmK2Source, "if (false) {", cond, 1)
			// compileScriptHex fails the test on any diagnostic.
			_ = compileScriptHex(t, source, disable)
		}
	}
}
