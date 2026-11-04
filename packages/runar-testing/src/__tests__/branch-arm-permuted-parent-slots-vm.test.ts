/**
 * Issue #178: a branch arm could REORDER the slots it inherits from the
 * enclosing scope and keep the same names at the same depth. The sibling arm
 * kept the old order, the parent kept modelling the old order, and after the
 * `if` every read of a moved slot on the permuted path took its neighbour's
 * value. Silent, in all seven tiers, in both fold modes.
 *
 * Two shapes produce the permutation:
 *
 *   1. An arm rebinds a local that is DEAD after the `if`. Nothing protects a
 *      dead local, so the rebind consumes the old slot (ROLL to top) and pushes
 *      the new value there: `w = w - 1n` turns `[w k]` into `[k w]`.
 *   2. A nested `if` without `else` rebinds a LIVE local. Its reconcile leaves
 *      the new value on top and drops the stale slot from beneath it, so inside
 *      the enclosing arm `[k m]` becomes `[m k]`.
 *
 * `lowerIf`'s reconcile compared the arms by name COUNT and DEPTH only, so
 * neither shape tripped anything. The reported repro needs both at once (a
 * nested write of `k2` and a dead `want = want - 1n`), but either alone is
 * enough: `DEAD_REBIND` below is four lines.
 *
 * THE FIX (`lowerIf` in 05-stack-lower, all seven tiers): before the reconcile
 * reads the arms by position, roll the slots each arm inherited back into the
 * parent's pre-`if` order (the contract the #149 `sinkBelow` repair keeps for
 * declared results). A new Layer D check then refuses, at compile time, any
 * pair of arms that still disagree slot by slot on a name the parent can read.
 *
 * `TestContract` interprets the AST, so it reports the SOURCE value and never
 * saw this. Every case below runs the emitted Script through `@bsv/sdk`'s
 * `Spend` (stateless: `TestSmartContract`'s `ScriptVM`; stateful: deploy and
 * call through `MockProvider` broadcast validation). Expected values are
 * derived BY HAND from the source, never from compiler output, and each
 * `rejects` value is what the miscompiled script used to ACCEPT, so these
 * cases cover a wrongly-spendable script as well as a locked one.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner } from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { TestSmartContract } from '../helpers.js';

/** A stateful contract with both shapes, deployed and spent below. */
const STATEFUL = `import { StatefulSmartContract } from 'runar-lang';

/**
 * BranchPermutedParentSlots -- the two ways a branch arm used to reorder the
 * slots it inherits from the enclosing scope while keeping the same names at
 * the same depth (issue #178). The sibling arm kept the old order, so after
 * the \`if\` one path read a neighbouring slot.
 *
 * deadRebind:   \`w\` is dead after the \`if\`; rebinding it in place consumed
 *               its slot and pushed the new value on top, over \`k\`.
 * nestedRebind: a nested \`if\` without \`else\` rebinds the live \`na\`, leaving
 *               the new value on top of \`nb\`.
 * siblingsAbove: the same under three siblings, so the then-arm has to sink
 *               \`na\` back under all three to restore the parent's order.
 */
class BranchPermutedParentSlots extends StatefulSmartContract {
  a: bigint;
  b: bigint;
  c: bigint;

  constructor(a: bigint, b: bigint, c: bigint) {
    super(a, b, c);
    this.a = a;
    this.b = b;
    this.c = c;
  }

  public deadRebind(x: bigint, flag: bigint) {
    let w: bigint = x + 1n;
    let k: bigint = x + 2n;
    if (flag > 0n) {
      w = w - 1n;
    }
    this.addOutput(1000n, k, this.b, this.c);
  }

  public nestedRebind(x: bigint, outer: bigint, inner: bigint) {
    let na: bigint = this.a;
    let nb: bigint = this.b;
    if (outer > 0n) {
      if (inner > 0n) {
        na = x + 1n;
      }
    }
    this.addOutput(1000n, na, nb, this.c);
  }

  public siblingsAbove(x: bigint, outer: bigint, inner: bigint) {
    let na: bigint = this.a;
    let s1: bigint = x + 1n;
    let s2: bigint = x + 2n;
    let s3: bigint = x + 3n;
    if (outer > 0n) {
      if (inner > 0n) {
        na = x;
      }
    }
    this.addOutput(1000n, na, s1 + s2, s3);
  }
}
`;

const PRIV = PrivateKey.fromString('b1'.repeat(32), 16);
const PKH = PRIV.toPublicKey().toHash('hex') as string;

function compileOrThrow(source: string, fileName: string, disableConstantFolding: boolean): RunarArtifact {
  const r = compile(source, { fileName, disableConstantFolding });
  if (!r.success || !r.artifact) {
    throw new Error(`compile failed: ${r.diagnostics.map((d) => d.message).join('; ')}`);
  }
  return r.artifact as RunarArtifact;
}

/** A stateless `check(a, b, expected)` around `body`. */
function stateless(name: string, body: string): string {
  return `import { SmartContract, assert } from 'runar-lang';

export class ${name} extends SmartContract {
  constructor() { super(); }

  public check(a: bigint, b: bigint, expected: bigint) {
${body}
  }
}
`;
}

/** The reproducer from the issue, verbatim. */
const ISSUE_178 = `import { SmartContract, assert } from 'runar-lang';
export class Desync extends SmartContract {
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
}
`;

/** Shape 1 alone: `w` is dead after the `if`, `k` is read. */
const DEAD_REBIND = stateless('DeadRebind', `    let w: bigint = a;
    let k: bigint = b;
    if (a > 0n) { w = w - 1n; }
    assert(k === expected);`);

/** Shape 1 with two live slots above the dead one. */
const DEAD_BELOW_TWO_LIVE = stateless('DeadBelowTwoLive', `    let w: bigint = a;
    let k: bigint = b;
    let m: bigint = a + b;
    if (a > 0n) { w = w - 1n; }
    assert(k * 100n + m === expected);`);

/** Shape 2 alone: no dead local anywhere. */
const NESTED_LIVE = stateless('NestedLive', `    let k: bigint = b;
    let m: bigint = a;
    if (a > 0n) { if (b > 0n) { k = 5n; } }
    assert(k * 100n + m === expected);`);

/**
 * Shape 2 with three siblings above `k`: the then-arm has to sink `k` back
 * under all three to restore the parent's `[k m1 m2 m3]`.
 */
const NESTED_LIVE_DEEP = stateless('NestedLiveDeep', `    let k: bigint = b;
    let m1: bigint = a;
    let m2: bigint = a + 1n;
    let m3: bigint = a + 2n;
    if (a > 0n) { if (b > 0n) { k = 5n; } }
    assert(k * 1000n + m1 * 100n + m2 * 10n + m3 === expected);`);

/**
 * Shape 2 under an `if` WITH an else, which takes the declared-results path:
 * `m` is the declared result, `k` is permuted beneath it.
 */
const NESTED_LIVE_ELSE = stateless('NestedLiveElse', `    let k: bigint = b;
    let m: bigint = a;
    if (a > 0n) { if (b > 0n) { k = 5n; } } else { m = m + 1n; }
    assert(k * 100n + m === expected);`);

type Case = {
  name: string;
  source: string;
  args: [bigint, bigint];
  expected: bigint;
  /** What the miscompiled script accepted instead, where it was derived by hand. */
  formerlyAccepted?: bigint;
};

const CASES: Case[] = [
  // k1 = 8; the nested arm writes k2 = 5. Main read `want` (0) for k2: 128.
  { name: 'the issue repro', source: ISSUE_178, args: [7n, 4n], expected: 133n, formerlyAccepted: 128n },
  // Condition false at the outer `if`: k2 stays 0 on every path.
  { name: 'the issue repro, outer if not taken', source: ISSUE_178, args: [7n, 3n], expected: 128n },
  // k = 9. Main read the rebound w = 3 - 1 = 2 for k.
  { name: 'dead rebind', source: DEAD_REBIND, args: [3n, 9n], expected: 9n, formerlyAccepted: 2n },
  { name: 'dead rebind, not taken', source: DEAD_REBIND, args: [-3n, 9n], expected: 9n },
  // k = 9, m = a + b: 912 taken, 906 not.
  { name: 'dead rebind below two live locals', source: DEAD_BELOW_TWO_LIVE, args: [3n, 9n], expected: 912n },
  { name: 'dead rebind below two live locals, not taken', source: DEAD_BELOW_TWO_LIVE, args: [-3n, 9n], expected: 906n },
  // k = 5, m = 3: 503. Main swapped them: 3 * 100 + 5 = 305.
  { name: 'nested live rebind', source: NESTED_LIVE, args: [3n, 9n], expected: 503n, formerlyAccepted: 305n },
  { name: 'nested live rebind, inner not taken', source: NESTED_LIVE, args: [3n, -9n], expected: -897n },
  // k = 5, m1..m3 = 3, 4, 5: 5345. Main read m1, m2, m3, k for k, m1, m2, m3:
  // 3 * 1000 + 4 * 100 + 5 * 10 + 5 = 3455.
  { name: 'nested live rebind under three siblings', source: NESTED_LIVE_DEEP, args: [3n, 9n], expected: 5345n, formerlyAccepted: 3455n },
  { name: 'nested live rebind under three siblings, inner not taken', source: NESTED_LIVE_DEEP, args: [3n, -9n], expected: -8655n },
  { name: 'nested live rebind under three siblings, outer not taken', source: NESTED_LIVE_DEEP, args: [-3n, 9n], expected: 8679n },
  // Then-arm: k = 5, m = 3. Else-arm: k = 9, m = -3 + 1 = -2.
  { name: 'nested live rebind beside a declared result', source: NESTED_LIVE_ELSE, args: [3n, 9n], expected: 503n },
  { name: 'nested live rebind beside a declared result, else arm', source: NESTED_LIVE_ELSE, args: [-3n, 9n], expected: 898n },
];

describe('issue #178: a branch arm keeps the parent slots it inherits in order', () => {
  for (const disableConstantFolding of [true, false]) {
    const mode = disableConstantFolding ? 'fold-OFF' : 'fold-ON';

    describe(mode, () => {
      it.each(CASES)('$name: Spend accepts the source value', ({ source, args, expected }) => {
        const artifact = compileOrThrow(source, 'C.runar.ts', disableConstantFolding);
        const r = TestSmartContract.fromArtifact(artifact, []).call('check', [...args, expected]);
        expect(r.success, r.error).toBe(true);
      });

      it.each(CASES.filter((c) => c.formerlyAccepted !== undefined))(
        '$name: Spend rejects the value the miscompile accepted',
        ({ source, args, formerlyAccepted }) => {
          const artifact = compileOrThrow(source, 'C.runar.ts', disableConstantFolding);
          const r = TestSmartContract.fromArtifact(artifact, []).call('check', [...args, formerlyAccepted!]);
          expect(r.success).toBe(false);
        },
      );
    });
  }
});

/** Compile -> deploy -> call, with the real `Spend` interpreter behind broadcast. */
async function deployAndCall(
  ctorArgs: unknown[],
  method: string,
  args: unknown[],
): Promise<Record<string, unknown>> {
  const artifact = compileOrThrow(STATEFUL, 'BranchPermutedParentSlots.runar.ts', false);
  const signer = new LocalSigner(PRIV.toString());
  const provider = new MockProvider();
  provider.enableBroadcastValidation();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: '76a914' + PKH + '88ac',
  });
  const contract = new RunarContract(artifact, ctorArgs);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 1000 });
  await contract.call(method, args, { satoshis: 1000 });
  return contract.state as Record<string, unknown>;
}

// The stateful contract above: a wrong slot is committed to the
// continuation, so the covenant's own hashOutputs check rejects the spend.
// Constructor state (a, b, c) = (5, 7, 9).
describe('issue #178: a stateful contract spends through MockProvider broadcast validation', () => {
  it('deadRebind, taken: k = x + 2 reaches the continuation', async () => {
    const state = await deployAndCall([5n, 7n, 9n], 'deadRebind', [10n, 1n]);
    expect(state).toEqual({ a: 12n, b: 7n, c: 9n });
  });

  it('nestedRebind, both taken: na = x + 1, nb keeps its value', async () => {
    const state = await deployAndCall([5n, 7n, 9n], 'nestedRebind', [30n, 1n, 1n]);
    expect(state).toEqual({ a: 31n, b: 7n, c: 9n });
  });

  it('nestedRebind, outer not taken: both keep their values', async () => {
    const state = await deployAndCall([5n, 7n, 9n], 'nestedRebind', [30n, 0n, 1n]);
    expect(state).toEqual({ a: 5n, b: 7n, c: 9n });
  });

  // The then-arm sinks `na` back under three siblings, so these cover a
  // restore deeper than a SWAP or ROT.
  it('siblingsAbove, both taken: na = x, the siblings keep their values', async () => {
    const state = await deployAndCall([5n, 7n, 9n], 'siblingsAbove', [10n, 1n, 1n]);
    expect(state).toEqual({ a: 10n, b: 23n, c: 13n });
  });

  it('siblingsAbove, outer not taken: na keeps its value', async () => {
    const state = await deployAndCall([5n, 7n, 9n], 'siblingsAbove', [10n, 0n, 1n]);
    expect(state).toEqual({ a: 5n, b: 23n, c: 13n });
  });
});
