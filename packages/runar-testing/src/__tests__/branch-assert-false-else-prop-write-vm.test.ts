/**
 * `if (guard) { this.prop = ... } else { assert(false) }` — the idiomatic
 * "reject anything that is not the happy path" guard.
 *
 * ===========================================================================
 * TWO DEFECTS, both found by an independent adversarial review of the
 * multi-result branch node (4b0f688f). Both produce a PERMANENTLY UNSPENDABLE
 * UTXO from source that reads as plainly correct — and deleting the `else`
 * makes both compile correctly, which is the tell that the `else` arm is what
 * the compiler mishandles.
 * ===========================================================================
 *
 * DEFECT 1 (P0-1) — the exclusion is wider than the rewrite it defers to.
 *
 * `lowerIfStatement` refuses to let an `if` declare `results` whenever
 * `collectUpdateBranches` returns non-null, on the grounds that
 * `liftBranchUpdateProps` will rewrite the `if` into flat conditional
 * assignments instead. But that pass only rewrites when the collector returns
 * TWO OR MORE branches. The `isAssertFalseElse` path returns a ONE-element
 * list — the then-arm's update, with the dead `assert(false)` else dropped —
 * so this shape was recognised, excluded from declaring results, and then not
 * rewritten either. It fell through both.
 *
 * What that produced: the then-arm's `update_prop` kept the property's old
 * stack slot, phase 3 of `lowerIf` gave the else arm an EMPTY placeholder
 * rather than a copy of the parent's value, and with `nResults === 1` the
 * N>=2 adopt path was skipped. The parent's model ended with the STALE value
 * of the property on top, and `lowerGetStateScript` resolves properties by
 * name through `findDepth`, which returns the TOPMOST slot. The state
 * continuation therefore committed the PRE-CALL value while the SDK (and the
 * off-chain interpreter) computed the post-call one, so `hashOutputs` never
 * matched and `OP_CHECKSIG` on the covenant preimage failed. The script ran to
 * the end and left a falsy top of stack.
 *
 * DEFECT 2 (P0-2) — the rewrite does not recurse, but the exclusion does.
 *
 * `liftBranchUpdateProps` runs over `method.body` ONLY, and passes `loop`
 * bodies and surviving `if` arms through untouched. `declaresResults`, by
 * contrast, is evaluated inside `lowerIfStatement` at EVERY nesting depth. So
 * a dispatch chain one `for` deeper — a chain the collector happily recognises
 * — was excluded from declaring results by a pass that would never reach it.
 * Two arms writing DIFFERENT property sets is exactly the shape the node was
 * built to fix, and nesting it inside a loop put it back out of reach.
 *
 * Both cases are asserted against post-state hand-derived from the source
 * semantics, and both are run through `@bsv/sdk`'s real `Spend` (via
 * `MockProvider.enableBroadcastValidation()`), so a continuation that commits
 * the wrong state is a test failure rather than a silent pass.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner } from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';

const PRIV = PrivateKey.fromString('b1'.repeat(32), 16);
const PKH = PRIV.toPublicKey().toHash('hex') as string;

/**
 * Compile -> deploy -> call, with @bsv/sdk's real `Spend` behind broadcast.
 *
 * `ctorArgs` is one zero per declared constructor parameter — every contract
 * here deploys from all-zero state, and the count differs only because a
 * contract declares one parameter per property (NEW-002: a parameter shared
 * between two properties has no slot of its own and is a compile error).
 */
async function run(
  source: string,
  fileName: string,
  disableConstantFolding: boolean,
  method: string,
  args: bigint[],
  ctorArgs: bigint[] = [0n],
): Promise<Record<string, unknown>> {
  const r = compile(source, { fileName, disableConstantFolding });
  if (!r.success || !r.artifact) {
    throw new Error(`compile failed: ${r.diagnostics.map((d) => d.message).join('; ')}`);
  }
  const signer = new LocalSigner(PRIV.toString());
  const provider = new MockProvider();
  provider.enableBroadcastValidation();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: '76a914' + PKH + '88ac',
  });
  const c = new RunarContract(r.artifact as never, ctorArgs);
  c.connect(provider, signer);
  await c.deploy({ satoshis: 1000 });
  await c.call(method, args, { satoshis: 1000 });
  return c.state as Record<string, unknown>;
}

/**
 * P0-1. One property written in the then-arm, `assert(false)` in the else.
 *
 * Hand-derived semantics: the contract deploys with `count = 0n` (the
 * constructor seeds it from its argument, which is `0n`). `bump(5n)` takes the
 * then-arm because `5n > 0n`, so the post-state is `count = 0n + 5n = 5n`.
 * Nothing else is written.
 */
const GUARD = `import { StatefulSmartContract } from 'runar-lang';

export class Guard extends StatefulSmartContract {
  count: bigint = 0n;
  constructor(seed: bigint) { super(seed); this.count = seed; }

  public bump(n: bigint) {
    if (n > 0n) { this.count = this.count + n; }
    else { assert(false); }
  }
}
`;

/**
 * P0-1, two properties. The then-arm writes two properties beside each other;
 * the else is still the dead guard. `collectUpdateBranches` still returns one
 * branch (`extractBranchUpdate` reads the arm's LAST binding), so this took
 * exactly the same excluded-and-not-rewritten path.
 *
 * Hand-derived: deploy `a = 0n, b = 0n`; `bump(5n)` gives `a = 5n`,
 * `b = 5n + 1n = 6n`.
 */
const GUARD2 = `import { StatefulSmartContract } from 'runar-lang';

export class Guard2 extends StatefulSmartContract {
  a: bigint = 0n;
  b: bigint = 0n;
  constructor(a: bigint, b: bigint) { super(a, b); this.a = a; this.b = b; }

  public bump(n: bigint) {
    if (n > 0n) { this.a = n; this.b = n + 1n; }
    else { assert(false); }
  }
}
`;

/**
 * P0-1 with a local beside the property — the two result KINDS in one arm,
 * under the assert-false guard rather than under a plain else.
 *
 * Hand-derived: deploy `a = 0n, b = 0n`; `bump(5n)` takes the then-arm, so
 * `k = 5n + 1n = 6n` and `this.a = 5n`, then `this.b = k = 6n`.
 */
const GUARD3 = `import { StatefulSmartContract } from 'runar-lang';

export class Guard3 extends StatefulSmartContract {
  a: bigint = 0n;
  b: bigint = 0n;
  constructor(a: bigint, b: bigint) { super(a, b); this.a = a; this.b = b; }

  public bump(n: bigint) {
    let k: bigint = 0n;
    if (n > 0n) { k = n + 1n; this.a = n; }
    else { assert(false); }
    this.b = k;
  }
}
`;

/**
 * P0-2. The dispatch chain `liftBranchUpdateProps` DOES recognise — two arms
 * writing different properties, `assert(false)` terminal else — but nested one
 * `for` deeper, where the lift pass never walks.
 *
 * Hand-derived: deploy `a = 0n, b = 0n`. `dispatch(0n, 7n)` runs the loop body
 * twice; both iterations take the `sel === 0n` arm and write `this.a = 7n`.
 * `b` is never written, so the post-state is `a = 7n, b = 0n`.
 */
const NESTED = `import { StatefulSmartContract } from 'runar-lang';

export class Nested extends StatefulSmartContract {
  a: bigint = 0n;
  b: bigint = 0n;
  constructor(a: bigint, b: bigint) { super(a, b); this.a = a; this.b = b; }

  public dispatch(sel: bigint, v: bigint) {
    for (let i = 0n; i < 2n; i++) {
      if (sel === 0n) { this.a = v; }
      else if (sel === 1n) { this.b = v; }
      else { assert(false); }
    }
  }
}
`;

/**
 * P0-2, the other unreachable position: the same chain nested inside another
 * `if`'s arm. `liftBranchUpdateProps` returns surviving `if` arms untouched
 * (it only rewrites top-level bindings of `method.body`), so an inner chain is
 * likewise recognised-but-never-rewritten.
 *
 * Hand-derived: deploy `a = 0n, b = 0n`. `dispatch(1n, 9n)` — the outer guard
 * `1n > 0n` holds, the inner chain takes `sel === 1n`, so `b = 9n` and `a`
 * stays `0n`.
 */
const NESTED_IF = `import { StatefulSmartContract } from 'runar-lang';

export class NestedIf extends StatefulSmartContract {
  a: bigint = 0n;
  b: bigint = 0n;
  constructor(a: bigint, b: bigint) { super(a, b); this.a = a; this.b = b; }

  public dispatch(sel: bigint, v: bigint) {
    if (v > 0n) {
      if (sel === 0n) { this.a = v; }
      else if (sel === 1n) { this.b = v; }
      else { assert(false); }
    } else {
      assert(false);
    }
  }
}
`;

for (const fold of [true, false]) {
  const mode = fold ? 'fold-OFF' : 'fold-ON';

  describe(`assert(false)-else guard with a property write (${mode})`, () => {
    it('P0-1: one property — commits the POST-call value, not the stale one', async () => {
      const state = await run(GUARD, 'Guard.runar.ts', fold, 'bump', [5n]);
      expect(state.count).toBe(5n);
    });

    it('P0-1: two properties in the guarded arm', async () => {
      const state = await run(GUARD2, 'Guard2.runar.ts', fold, 'bump', [5n], [0n, 0n]);
      expect(state.a).toBe(5n);
      expect(state.b).toBe(6n);
    });

    it('P0-1: a local beside the property in the guarded arm', async () => {
      const state = await run(GUARD3, 'Guard3.runar.ts', fold, 'bump', [5n], [0n, 0n]);
      expect(state.a).toBe(5n);
      expect(state.b).toBe(6n);
    });

    it('P0-1: the guard still REJECTS the arm it guards against', async () => {
      await expect(run(GUARD, 'Guard.runar.ts', fold, 'bump', [0n])).rejects.toThrow();
    });
  });

  describe(`dispatch chain out of liftBranchUpdateProps' reach (${mode})`, () => {
    it('P0-2: chain inside a loop body', async () => {
      const state = await run(NESTED, 'Nested.runar.ts', fold, 'dispatch', [0n, 7n], [0n, 0n]);
      expect(state.a).toBe(7n);
      expect(state.b).toBe(0n);
    });

    it('P0-2: chain inside another if arm', async () => {
      const state = await run(NESTED_IF, 'NestedIf.runar.ts', fold, 'dispatch', [1n, 9n], [0n, 0n]);
      expect(state.a).toBe(0n);
      expect(state.b).toBe(9n);
    });

    it('P0-2: the nested chain still rejects an unmatched selector', async () => {
      await expect(
        run(NESTED_IF, 'NestedIf.runar.ts', fold, 'dispatch', [5n, 9n], [0n, 0n]),
      ).rejects.toThrow();
    });
  });
}
