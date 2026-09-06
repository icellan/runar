import { describe, it, expect } from 'vitest';
import { TestContract } from '../test-contract.js';
import { runStatefulSpend } from '../oracle/real-crypto-execution.js';

/**
 * NEW-019 — the depth-balance PAD displaced the whole INHERITED region of an
 * arm that produced no result, and deployed to a permanently unspendable UTXO.
 *
 *     public settle(mode: bigint, delta: bigint): void {
 *       if (mode < 0n) {
 *         assert(delta < -1n);        // consumes `delta`, leaves a dead `1n`
 *       } else {
 *         assert(this.epoch > 0n);    // consumes nothing, leaves nothing
 *       }
 *       this.balance = 60n;
 *       this.addOutput(1n, this.balance, this.epoch);
 *     }
 *
 * With `mode = 20n` the ELSE arm runs, `this.epoch > 0n` is true, and the
 * method writes its continuation. The source ACCEPTS and `TestContract`
 * accepts. `@bsv/sdk`'s real `Spend` rejects the spend with "The top stack
 * element must be truthy after script evaluation" — an ordinary contract, with
 * no `&&`, no `||` and no nesting, deployed to an unspendable UTXO.
 *
 * ROOT CAUSE
 * ----------
 * The two arms reach phase 3 of `lowerIf` at different depths. The then-arm
 * ROLLed `delta` away (its only reader) and kept ONE slot of its own — the
 * dead `1n` that lowering a negative literal leaves behind, which
 * `drainBranchPrivateResidue` preserves because it is the arm's TOS. The
 * else-arm read `this.epoch` through a PICK, so it gave up nothing and
 * produced nothing: its stack IS the region it inherited.
 *
 * Phase 1 makes the else-arm drop `delta` too, and phase 3 then owes it one
 * slot. NEW-017 taught phase 3 to tuck that pad UNDER the arm's top slot,
 * because the arm it was fixing held its OWN result there and the pad was
 * landing on top of it. This arm holds no result there — the slot is
 * `this.epoch`, inherited — so the swap pushed the ENTIRE inherited region one
 * slot deeper:
 *
 *     then path   [ 1n     epoch  balance … ]     (matches the parent model)
 *     else path   [ epoch  <pad>  balance … ]     (off by one from `epoch` down)
 *     parent      [ t22    epoch  balance … ]
 *
 * `addOutput` then read the pad where `this.epoch` should be, committed an
 * empty `epoch` into the continuation, and the auto-injected output-hash check
 * failed. Both faces are fund-safety bugs: the spend the source allows is
 * rejected (funds locked), and the state that WOULD have been committed is not
 * the state the source computes.
 *
 * THE FIX
 * -------
 * Decide the pad's position POSITIONALLY, not by depth — both shapes reach
 * phase 3 at the same depth, so depth cannot tell them apart. The arm has no
 * result of its own exactly when its stack, top-down, IS the parent's post-`if`
 * model (the parent's slots minus the ones both arms gave up, which is what the
 * post-OP_ENDIF reconcile removes). Then the pad IS the result placeholder and
 * belongs ON TOP. NEW-017's arm fails that test on slot 0 — it holds a
 * branch-private result name where the model holds the parent's own TOS — and
 * keeps the swap. `branch-pad-below-result-vm.test.ts` is the control for it.
 */

const FILE = 'Ledger.runar.ts';

const SRC = `import { StatefulSmartContract, assert } from 'runar-lang';

export class Ledger extends StatefulSmartContract {
  balance: bigint;
  epoch: bigint;

  constructor(balance: bigint, epoch: bigint) {
    super(balance, epoch);
    this.balance = balance;
    this.epoch = epoch;
  }

  public settle(mode: bigint, delta: bigint): void {
    if (mode < 0n) {
      assert(delta < -1n);
    } else {
      assert(this.epoch > 0n);
    }
    this.balance = 60n;
    this.addOutput(1n, this.balance, this.epoch);
  }
}
`;

/**
 * CONTROL. Identical but for the sign of the then-arm's literal. A POSITIVE
 * literal leaves no dead constant, so the arms reach phase 3 at equal depth and
 * no pad is emitted at all — this case was green before the fix and pins that
 * the fix did not simply stop padding.
 */
const CONTROL_NO_PAD = SRC.replace('delta < -1n', 'delta < 5n');

/**
 * CONTROL. The else-arm now PRODUCES a result of its own (the dead `1n` of its
 * own negative literal), so both arms hold a result and the inherited region is
 * identical in both — the shape the pad logic must leave untouched.
 */
const CONTROL_BOTH_ARMS_RESIDUE = SRC.replace('this.epoch > 0n', 'this.epoch > -1n');

interface Case {
  readonly label: string;
  readonly source: string;
  /** [mode, delta] => what the SOURCE says, and therefore what both engines must say. */
  readonly expect: ReadonlyArray<readonly [bigint, bigint, boolean]>;
}

const CTOR: [bigint, bigint] = [1n, 7n];

const CASES: Case[] = [
  {
    label: 'the arm that produced no result keeps its inherited region',
    source: SRC,
    expect: [
      // else arm: epoch = 7 > 0 => ACCEPT. This is the miscompile.
      [20n, -20n, true],
      // then arm: -20 < -1 => ACCEPT. This path was already correct.
      [-3n, -20n, true],
      // then arm: 0 < -1 is false => the guard must still REJECT.
      [-3n, 0n, false],
    ],
  },
  {
    label: 'CONTROL no dead constant, so no pad is emitted',
    source: CONTROL_NO_PAD,
    expect: [
      [20n, -20n, true],
      [-3n, -20n, true],
      [-3n, 9n, false],
    ],
  },
  {
    label: 'CONTROL both arms leave a result of their own',
    source: CONTROL_BOTH_ARMS_RESIDUE,
    expect: [
      [20n, -20n, true],
      [-3n, -20n, true],
      [-3n, 0n, false],
    ],
  },
];

describe('NEW-019 — the branch depth pad must not displace the inherited region', () => {
  for (const c of CASES) {
    for (const [mode, delta, accepts] of c.expect) {
      it(`${c.label}: settle(${mode}, ${delta}) => ${accepts ? 'ACCEPT' : 'REJECT'} on the real engine`, async () => {
        const r = await runStatefulSpend({
          source: c.source,
          fileName: FILE,
          method: 'settle',
          args: [mode, delta],
          constructorArgs: CTOR,
          signerKey: 'alice',
          satoshis: 1,
        });
        expect(r.reachedEngine, `never reached Spend: ${r.vmError ?? ''}`).toBe(true);
        expect(
          r.vmAccepted,
          `the real engine disagreed with the source: ${r.vmError ?? '(accepted)'}`,
        ).toBe(accepts);
        if (accepts) {
          // Accept alone is not enough: a pad in the wrong slot commits the
          // WRONG continuation, which is the silent half of the defect.
          expect(r.continuationState).toEqual({ balance: 60n, epoch: 7n });
        }
      });

      it(`${c.label}: settle(${mode}, ${delta}) => TestContract agrees`, () => {
        const contract = TestContract.fromSource(
          c.source,
          { balance: CTOR[0], epoch: CTOR[1] },
          FILE,
        );
        const res = contract.call('settle', { mode, delta });
        expect(res.success, `TestContract: ${res.error ?? ''}`).toBe(accepts);
        if (accepts) expect(contract.state).toEqual({ balance: 60n, epoch: 7n });
      });
    }
  }
});
