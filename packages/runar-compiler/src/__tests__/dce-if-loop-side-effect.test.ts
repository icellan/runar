/**
 * R-006 — TypeScript DCE must not delete an `if` / `loop` whose *nested*
 * bindings carry observable side effects.
 *
 * ## The defect
 *
 * `optimizer/dce.ts`'s `hasSideEffect` listed `'if'` and `'loop'` under the
 * comment "Pure ANF kinds — no side effect, safe to DCE if unreferenced" and
 * returned `false` for both.
 *
 * Nested bindings live INSIDE the parent `if`/`loop` node rather than being
 * flattened into the method body, so binding retention is all-or-nothing: an
 * unreferenced `if` takes every nested `assert`, `check_preimage` and
 * `add_output` with it. `04-anf-lower.ts`'s statement-`if` lowering produces
 * exactly such an unreferenced binding for the ordinary guard shape
 * `if (flag) { assert(...) }` — one arm, no rebound local, no output — so
 * nothing in the surrounding method ever references the `if` binding's name.
 *
 * DCE reaches the main `compile()` pipeline only from inside
 * `optimizer/anf-ec.ts`'s `optimizeEC`, behind its `anyChanged` gate, and that
 * gate is program-wide: a single foldable EC call ANYWHERE in the contract arms
 * a DCE sweep over EVERY method. That is what makes this reachable from
 * ordinary source rather than theoretical — the guard clauses vanish and the
 * result still compiles to valid, non-erroring script.
 *
 * This is the TypeScript arm of the same defect fixed for Rust in 10beeb99.
 *
 * ## What these tests prove
 *
 * - `guardClauseSurvivesEcOptimizerDce` is the end-to-end regression: it drives
 *   the real `compile()` pipeline (parse → validate → typecheck → ANF → fold →
 *   optimizeEC/DCE) on the reproduction contract and asserts the `if` binding
 *   and its nested `pubKeyHash` assert survive. It exercises the actual
 *   deletion, not just the predicate.
 * - The predicate / pass-level tests pin both polarities: nested effects keep
 *   the node, a genuinely pure `if`/`loop` stays DCE-eligible.
 *
 * ## What these tests do NOT prove
 *
 * They say nothing about the emitted *hex* of a retained guard being
 * semantically correct — only that the binding is no longer dropped. They cover
 * the TypeScript tier only. They do not prove `hasSideEffect` is exhaustive over
 * future ANF kinds beyond the `UnknownANFKindError` the `default` arm throws.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { eliminateDeadBindings, hasSideEffect } from '../optimizer/dce.js';
import type {
  ANFProgram,
  ANFMethod,
  ANFBinding,
  ANFValue,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// End-to-end: the real deletion
// ---------------------------------------------------------------------------

/** Guard clause + a foldable `ecMulGen(1n)` to arm `optimizeEC`'s DCE sweep. */
const GUARD_WITH_EC_TRIGGER = `import { SmartContract, assert, ByteString, Sig, PubKey, hash160, checkSig, ecMulGen } from 'runar-lang';

class Guard extends SmartContract {
  readonly pubKeyHash: ByteString;

  constructor(pubKeyHash: ByteString) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey, flag: boolean): void {
    assert(checkSig(sig, pubKey));
    if (flag) {
      assert(hash160(pubKey) === this.pubKeyHash);
    }
    const g: ByteString = ecMulGen(1n);
    assert(g !== this.pubKeyHash);
  }
}`;

describe('R-006: TypeScript DCE and nested side effects', () => {
  it('keeps the guard clause through the EC optimizer DCE sweep', () => {
    const result = compile(GUARD_WITH_EC_TRIGGER, { fileName: 'Guard.runar.ts' });
    expect(result.success, JSON.stringify(result.diagnostics)).toBe(true);
    expect(result.anf).not.toBeNull();

    const unlock = result.anf!.methods.find((m) => m.name === 'unlock');
    expect(unlock, 'unlock method present').toBeDefined();

    const ifBinding = unlock!.body.find((b) => b.value.kind === 'if');
    expect(
      ifBinding,
      'the `if (flag) { assert(...) }` guard was eliminated by DCE; surviving bindings: ' +
        unlock!.body.map((b) => `${b.name}:${b.value.kind}`).join(', '),
    ).toBeDefined();

    // ...and the guard's assert must still be inside it.
    const ifValue = ifBinding!.value;
    if (ifValue.kind !== 'if') throw new Error('narrowed above');
    expect(
      ifValue.then.some((b) => b.value.kind === 'assert'),
      'retained `if` lost its nested assert',
    ).toBe(true);
    expect(
      ifValue.then.some(
        (b) => b.value.kind === 'load_prop' && b.value.name === 'pubKeyHash',
      ),
      'retained `if` lost the `this.pubKeyHash` load it guards on',
    ).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Predicate + pass-level behaviour, both polarities
  // -------------------------------------------------------------------------

  function b(name: string, value: ANFValue): ANFBinding {
    return { name, value };
  }

  function loadTrue(name: string): ANFBinding {
    return b(name, { kind: 'load_const', value: true });
  }

  function assertOn(name: string, target: string): ANFBinding {
    return b(name, { kind: 'assert', value: target });
  }

  function methodWith(body: ANFBinding[]): ANFMethod {
    return { name: 'm', params: [], body, isPublic: true };
  }

  function programWith(body: ANFBinding[]): ANFProgram {
    return { contractName: 'T', properties: [], methods: [methodWith(body)] };
  }

  it('treats an `if` whose arm asserts as effectful', () => {
    const node: ANFValue = {
      kind: 'if',
      cond: 'c',
      then: [loadTrue('n0'), assertOn('n1', 'n0')],
      else: [],
    };
    expect(hasSideEffect(node)).toBe(true);
  });

  it('treats a `loop` whose body asserts as effectful', () => {
    const node: ANFValue = {
      kind: 'loop',
      count: 1,
      body: [loadTrue('n0'), assertOn('n1', 'n0')],
      iterVar: 'i',
      start: 0n,
      step: 1,
    };
    expect(hasSideEffect(node)).toBe(true);
  });

  it('leaves a pure `if` DCE-eligible (negative control)', () => {
    const node: ANFValue = {
      kind: 'if',
      cond: 'c',
      then: [loadTrue('n0')],
      else: [loadTrue('n1')],
    };
    expect(hasSideEffect(node)).toBe(false);
  });

  /** The single method's surviving binding names, after DCE. */
  function survivingNames(program: ANFProgram): string[] {
    const method = program.methods[0];
    if (method === undefined) throw new Error('DCE dropped the method itself');
    return method.body.map((x) => x.name);
  }

  it('keeps an unreferenced `if` that contains an assert', () => {
    const out = eliminateDeadBindings(
      programWith([
        loadTrue('c'),
        b('t_if', {
          kind: 'if',
          cond: 'c',
          then: [loadTrue('n0'), assertOn('n1', 'n0')],
          else: [],
        }),
      ]),
    );
    expect(
      survivingNames(out).includes('t_if'),
      'DCE deleted an unreferenced `if` that contains an assert',
    ).toBe(true);
  });

  it('still drops a pure unreferenced `if` (negative control)', () => {
    const out = eliminateDeadBindings(
      programWith([
        loadTrue('c'),
        b('t_if', {
          kind: 'if',
          cond: 'c',
          then: [loadTrue('n0')],
          else: [],
        }),
        // A real effect so the method is not entirely elided.
        loadTrue('k'),
        assertOn('k_assert', 'k'),
      ]),
    );
    expect(
      survivingNames(out).includes('t_if'),
      'a pure unreferenced `if` should still be eliminated',
    ).toBe(false);
  });
});
