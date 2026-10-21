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
			// N-216 (2026-10-21): re-pinned; the branch-reconcile rolls now fold (`<k> OP_ROLL` -> OP_SWAP / OP_ROT), opcode diff is folds only, -1 B per fold.
			"00014e01ce006351547a6e7b757b7567527978557a75687b75537a757b7c7ba177"},
		{"dead-arm-k2/fold-off", deadArmK2Source, true,
			"00014e8f006351537a6e7b757b75676e547a75687b757b757ca1"},
		{"self-read-both-arms/fold-on", selfReadBothArmsSource, false,
			"000340420f0340428f7b7ca069517b00a06351787c9376776751787c947677687c750340420f0340428f7b7ca07777"},
		{"self-read-both-arms/fold-off", selfReadBothArmsSource, true,
			"000340420f8fa069517c00a06351787c9376776751787c947677687c750340420f8fa0"},
		{"const-condition-k1/fold-on", constConditionK1Source, false,
			"000340420f0340428f7b7ca06951516352767767537677687c750340420f0340428f7b7ca0777777"},
		{"const-condition-k1/fold-off", constConditionK1Source, true,
			"000340420f8fa06951516352767767537677687c750340420f8fa077"},
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
//
// F-311: as written up to 2026-10-11, this test only did
// `_ = compileScriptHex(t, source, disable)` — it compiled 6 variants (3
// conditions x 2 fold settings) and asserted nothing about the bytes any of
// them produced, despite its name claiming "const and runtime conditions
// agree". compileScriptHex only fails on a diagnostic/panic, so the test
// passed on ANY compiled output, including a wrong one. Confirmed by
// instrumenting lowerIf's declared-results adoption block in codegen/stack.go
// — specifically the POST-ENDIF stale-slot roll-out it runs for `nDeclared
// >= 1` (`for d := nDeclared; d < ctx.sm.depth(); d++`, the loop that
// computes `sinkBelow`) — to push `d+1` instead of `d` as the OP_ROLL operand
// while leaving the stackMap bookkeeping (`ctx.sm.push` / `pop` /
// `removeAtDepth(d)`) untouched: the compiler's own layout and depth
// invariants only check the SYMBOLIC model, which the mutation never
// touches, so they stayed green while the emitted OP_ROLL silently targeted
// one slot too deep in all six cases. The pre-fix body of this test passed
// unchanged against that mutation.
//
// What "agree" actually means here, verified against the real compiler
// output: for a fixed fold setting, deadArmK2Source's k=2 dead-arm merge
// lowers the SAME bytes from OP_IF onward (branch body, trim, and the
// post-ENDIF reconcile) no matter whether the condition is the constant
// `false`, the constant `true`, or the runtime comparison `p > 0n` — only the
// condition-push bytes immediately before OP_IF (0x63) differ. That is
// exactly the invariant frontend/constant_fold.go's "if" case and
// codegen/stack.go's result-adoption code (both referenced above) are meant
// to guarantee: folding never special-cases a statically-known condition
// in the branch-merge machinery.
//
// What this does NOT prove: that the pinned bytes are correct Bitcoin
// Script — that's TestBranchMergeK1AndDeadArm_SevenTierScript's cross-tier
// pin (which the "false" cases here are cross-checked against) plus the
// on-chain/ScriptVM oracles, neither of which this test runs. It also does
// not prove any OTHER tier agrees on the `true` / `p > 0n` variants — these
// hexes are Go-only. And lowerIf has no access to whether `cond` is a
// compile-time constant (it only ever sees the stack-map name "cond"), so
// EVERY mutation found here — including the one used to prove this test can
// go red — changes bytes for false/true/p>0n uniformly; the exact-hex pins
// are what catch that, not the HasSuffix check (a cond-specific regression,
// if one is ever introduced via constant_fold.go's "if" case, would be
// caught the same way, by the pins moving).
func TestBranchMergeK1AndDeadArm_ConstAndRuntimeConditionsAgree(t *testing.T) {
	// Exact hexes, measured against the current compiler (not copied from a
	// reviewer or a golden file): the fix being guarded is Go-tier-internal
	// branch-merge lowering, so this is deliberately NOT a cross-tier
	// conformance golden (unlike TestBranchMergeK1AndDeadArm_SevenTierScript
	// above). "false"/fold-on and "false"/fold-off match that test's
	// dead-arm-k2 cases exactly, which is the cross-check that these were
	// captured correctly.
	cases := []struct {
		cond       string
		foldOnHex  string
		foldOffHex string
	}{
		{"if (false) {",
			"00014e01ce006351547a6e7b757b7567527978557a75687b75537a757b7c7ba177",
			"00014e8f006351537a6e7b757b75676e547a75687b757b757ca1"},
		{"if (true) {",
			"00014e01ce516351547a6e7b757b7567527978557a75687b75537a757b7c7ba177",
			"00014e8f516351537a6e7b757b75676e547a75687b757b757ca1"},
		{"if (p > 0n) {",
			"00014e01ce537900a06351547a6e7b757b7567527978557a75687b75537a757b7c7ba177",
			"00014e8f527900a06351537a6e7b757b75676e547a75687b757b757ca1"},
	}

	// The shared tail every case above must end with: the condition-push
	// prefix is the only part allowed to vary. Starts at "63" (OP_IF).
	const foldOnSuffix = "6351547a6e7b757b7567527978557a75687b75537a757b7c7ba177"
	const foldOffSuffix = "6351537a6e7b757b75676e547a75687b757b757ca1"

	for _, tc := range cases {
		source := strings.Replace(deadArmK2Source, "if (false) {", tc.cond, 1)

		gotOn := compileScriptHex(t, source, false)
		if gotOn != tc.foldOnHex {
			t.Errorf("cond=%q fold-on: hex changed\n got  %s\n want %s", tc.cond, gotOn, tc.foldOnHex)
		}
		if !strings.HasSuffix(gotOn, foldOnSuffix) {
			gotSuffix := gotOn
			if len(gotOn) > len(foldOnSuffix) {
				gotSuffix = gotOn[len(gotOn)-len(foldOnSuffix):]
			}
			t.Errorf("cond=%q fold-on: branch body/merge bytes (from OP_IF onward) diverged from the shared post-OP_IF tail\n got suffix  ...%s\n want suffix ...%s", tc.cond, gotSuffix, foldOnSuffix)
		}

		gotOff := compileScriptHex(t, source, true)
		if gotOff != tc.foldOffHex {
			t.Errorf("cond=%q fold-off: hex changed\n got  %s\n want %s", tc.cond, gotOff, tc.foldOffHex)
		}
		if !strings.HasSuffix(gotOff, foldOffSuffix) {
			gotSuffix := gotOff
			if len(gotOff) > len(foldOffSuffix) {
				gotSuffix = gotOff[len(gotOff)-len(foldOffSuffix):]
			}
			t.Errorf("cond=%q fold-off: branch body/merge bytes (from OP_IF onward) diverged from the shared post-OP_IF tail\n got suffix  ...%s\n want suffix ...%s", tc.cond, gotSuffix, foldOffSuffix)
		}
	}
}
