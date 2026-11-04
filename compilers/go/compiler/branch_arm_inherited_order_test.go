package compiler

// Issue #178: a branch arm reordered the slots it inherited from the
// enclosing scope, pinned to the seven-tier script.
//
// Mirrors packages/runar-compiler/src/__tests__/branch-arm-inherited-order.test.ts.
//
// An arm could permute the parent's slots and keep the same names at the same
// depth. The reconcile compared the arms by name count and depth only, the
// sibling arm kept the parent's order, and after the `if` every read of a moved
// slot on the permuted path took its neighbour's value. Silent in all seven
// tiers, fold on and off.
//
//   dead-rebind  `w` is dead after the `if`, so `w = w - 1n` consumes its slot
//                and pushes the new value on top of `k`.
//   nested-live  a nested `if` without `else` rebinds the live `k`, leaving the
//                new value on top of `m`.
//   nested-live-deep
//                the same under three siblings: the then-arm sinks `k` back
//                under all three to restore the parent's order.
//   issue-repro  the reported shape, which has both.
//
// Fix: before the reconcile reads the arms by position, lowerIf brings their
// inherited slots back into the parent's pre-`if` order, the contract the
// #149 sinkBelow repair keeps for declared results.
//
// The hexes are the SEVEN-TIER agreed output. Every tier pins the same strings,
// which is what makes this a parity gate.

import "testing"

const deadRebindSource = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  constructor() { super(); }

  public check(a: bigint, b: bigint, expected: bigint) {
    let w: bigint = a;
    let k: bigint = b;
    if (a > 0n) { w = w - 1n; }
    assert(k === expected);
  }
}`

const nestedLiveSource = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  constructor() { super(); }

  public check(a: bigint, b: bigint, expected: bigint) {
    let k: bigint = b;
    let m: bigint = a;
    if (a > 0n) { if (b > 0n) { k = 5n; } }
    assert(k * 100n + m === expected);
  }
}`

const nestedLiveDeepSource = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  constructor() { super(); }

  public check(a: bigint, b: bigint, expected: bigint) {
    let k: bigint = b;
    let m1: bigint = a;
    let m2: bigint = a + 1n;
    let m3: bigint = a + 2n;
    if (a > 0n) { if (b > 0n) { k = 5n; } }
    assert(k * 1000n + m1 * 100n + m2 * 10n + m3 === expected);
  }
}`

const issueReproSource = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  constructor() { super(); }

  public check(a: bigint, e: bigint, expected: bigint) {
    let c4: bigint = 0n;
    if (e === 4n) { c4 = c4 + 1n; }
    let q: bigint = 0n;
    if (a === 7n) { q = 8n; }
    let k1: bigint = 0n;
    let k2: bigint = 0n;
    let ex1: bigint = 0n;
    let want: bigint = 0n;
    let slot: bigint = 0n;
    if (q > 0n) { k1 = q; ex1 = q; want = 1n; slot = 2n; }
    let pr: bigint = 0n;
    if (c4 > 0n) { pr = 1n; }
    if (want > 0n && pr > 0n && ex1 !== 5n) {
      if (slot === 2n) { k2 = 5n; }
      want = want - 1n;
    }
    assert(k1 * 16n + k2 === expected);
  }
}`

func TestBranchArmInheritedOrder_SevenTierScript(t *testing.T) {
	cases := []struct {
		label                  string
		source                 string
		disableConstantFolding bool
		want                   string
	}{
		{"dead-rebind/fold-on", deadRebindSource, false,
			"52797b537a00a063517b7c947c687b9c77"},
		{"dead-rebind/fold-off", deadRebindSource, true,
			"52797b537a00a063517b7c947c687b9c77"},
		{"nested-live/fold-on", nestedLiveSource, false,
			"785379547a00a063537a00a063556778687b757c67537a756801647b7c957c937c9c"},
		{"nested-live/fold-off", nestedLiveSource, true,
			"785379547a00a063537a00a063556778687b757c67537a756801647b7c957c937c9c"},
		{"nested-live-deep/fold-on", nestedLiveDeepSource, false,
			"78537954798b55795293567a00a063557a00a0635567537968547a75537a537a537a67557a756802e803547a7c950164547a7c95935a537a7c95937c937c9c"},
		{"nested-live-deep/fold-off", nestedLiveDeepSource, true,
			"78537954798b55795293567a00a063557a00a0635567537968547a75537a537a537a67557a756802e803547a7c950164547a7c95935a537a7c95937c937c9c"},
		{"issue-repro/fold-on", issueReproSource, false,
			"007b549c63516776687700537a579c63586776687700000000000056797ca0635579567951525379537953795379537a537a537a537a547a75547a75547a75547a75675479537953795379537a537a537a537a68547a75547a75547a75557a75547a0000587a7ca06351677668770054797ca06300a0670077686355547a7c9c916700547a756863527b7c9c635567766877517b7c947c67776860537a7c957c93537a9c7777"},
		{"issue-repro/fold-off", issueReproSource, true,
			"007b549c6351787c936776687700537a579c63586776687700000000000056797ca0635579567951525379537953795379537a537a537a537a547a75547a75547a75547a75675479537953795379537a537a537a537a68547a75547a75547a75557a75547a0000587a7ca06351677668770054797ca06300a0670077686355547a7c9c916700547a756863527b7c9c635567766877517b7c947c67776860537a7c957c93537a9c7777"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			// compileScriptHex is defined in branch_merge_dead_arm_k1_test.go.
			got := compileScriptHex(t, tc.source, tc.disableConstantFolding)
			if got != tc.want {
				t.Fatalf("script hex diverged from the seven-tier agreed output\n want %s\n  got %s", tc.want, got)
			}
		})
	}
}
