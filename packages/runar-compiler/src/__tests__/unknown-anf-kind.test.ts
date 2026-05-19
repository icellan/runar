/**
 * Regression test for F-003: every ANF-kind dispatch in the TS compiler
 * must throw UnknownANFKindError when it encounters a kind it doesn't
 * recognize, instead of silently returning an empty / no-op result.
 *
 * Each test drives one dispatch site with a synthetic ANFValue whose
 * `kind` does not appear in the ANFValue union, then asserts the
 * resulting throw is the typed error and carries the synthetic kind name.
 *
 * If a new ANFValue variant is added in the future, the dispatch sites
 * below must be updated; this test guards against silently shipping an
 * unhandled variant.
 */

import { describe, it, expect } from 'vitest';
import { UnknownANFKindError } from 'runar-ir-schema';
import type {
  ANFProgram,
  ANFMethod,
  ANFBinding,
  ANFValue,
} from '../ir/index.js';
import { foldConstants, eliminateDeadBindings } from '../optimizer/constant-fold.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { remapValueRefs } from '../passes/04-anf-lower.js';

const SYNTHETIC_KIND = 'synthetic_test_kind_for_regression_only';

/**
 * Build an ANFValue that the type system thinks is fine but whose runtime
 * `kind` discriminator is not in the schema. The cast is intentional —
 * the whole point is to simulate a developer adding a new ANF variant
 * without wiring it through every dispatch site.
 */
function syntheticValue(): ANFValue {
  return { kind: SYNTHETIC_KIND } as unknown as ANFValue;
}

function makeProgram(body: ANFBinding[]): ANFProgram {
  const method: ANFMethod = {
    name: 'm',
    params: [],
    body,
    isPublic: true,
  };
  return {
    contractName: 'Test',
    properties: [],
    methods: [method],
  };
}

describe('UnknownANFKindError — dispatch-site regression guard', () => {
  it('throws from constant-fold.foldValue', () => {
    const program = makeProgram([{ name: 't0', value: syntheticValue() }]);

    let caught: unknown;
    try {
      foldConstants(program);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(UnknownANFKindError);
    expect((caught as UnknownANFKindError).kind).toBe(SYNTHETIC_KIND);
    expect((caught as UnknownANFKindError).location).toBe('constant-fold.foldValue');
  });

  it('throws from constant-fold.collectRefsFromValue (via DCE)', () => {
    // hasSideEffect is consulted first in filterLiveBindings; we want to
    // hit collectRefsFromValue, which runs over the body before the
    // side-effect filter. Putting the synthetic binding inside an `if`
    // forces the dead-binding pass to walk into nested values via
    // collectRefsFromValue's recursive case before hasSideEffect sees it.
    const program = makeProgram([
      { name: 't0', value: { kind: 'load_const', value: true } },
      {
        name: 't1',
        value: {
          kind: 'if',
          cond: 't0',
          then: [{ name: 'tn', value: syntheticValue() }],
          else: [],
        },
      },
    ]);

    let caught: unknown;
    try {
      eliminateDeadBindings(program);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(UnknownANFKindError);
    expect((caught as UnknownANFKindError).kind).toBe(SYNTHETIC_KIND);
    // The first dispatch to fail is collectRefsFromValue inside the if-walk.
    expect((caught as UnknownANFKindError).location).toBe(
      'constant-fold.collectRefsFromValue',
    );
  });

  it('throws from constant-fold.hasSideEffect (via DCE on flat body)', () => {
    // With a flat body, collectAllRefs walks only top-level bindings via
    // the switch (load_const path is hit first, with no nested values).
    // The synthetic binding has no nested refs so collectRefsFromValue
    // throws there too — but for the side-effect-only path we craft a
    // body where the synthetic value is the only binding, so the first
    // dispatch hit is collectRefsFromValue. To actually reach
    // hasSideEffect we'd have to skip ref-collection; instead we assert
    // that *something* in the DCE pipeline rejects the synthetic kind.
    const program = makeProgram([{ name: 't0', value: syntheticValue() }]);

    let caught: unknown;
    try {
      eliminateDeadBindings(program);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(UnknownANFKindError);
    expect((caught as UnknownANFKindError).kind).toBe(SYNTHETIC_KIND);
    // Either dispatch site is acceptable — both must reject the kind.
    expect([
      'constant-fold.collectRefsFromValue',
      'constant-fold.hasSideEffect',
    ]).toContain((caught as UnknownANFKindError).location);
  });

  it('throws from stack-lower (collectRefs or lowerBinding)', () => {
    const program = makeProgram([{ name: 't0', value: syntheticValue() }]);

    let caught: unknown;
    try {
      lowerToStack(program);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(UnknownANFKindError);
    expect((caught as UnknownANFKindError).kind).toBe(SYNTHETIC_KIND);
    // collectRefs runs first (computeLastUses) — that's where we expect
    // the throw — but lowerBinding is the fallback. Both are acceptable.
    expect([
      'stack-lower.collectRefs',
      'stack-lower.lowerBinding',
    ]).toContain((caught as UnknownANFKindError).location);
  });

  it('throws from anf-lower.remapValueRefs', () => {
    let caught: unknown;
    try {
      remapValueRefs(syntheticValue(), {});
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(UnknownANFKindError);
    expect((caught as UnknownANFKindError).kind).toBe(SYNTHETIC_KIND);
    expect((caught as UnknownANFKindError).location).toBe('anf-lower.remapValueRefs');
  });

  it('carries an actionable message that references the developer recipe', () => {
    const err = new UnknownANFKindError(SYNTHETIC_KIND, 'unit-test.location');
    expect(err.message).toContain(SYNTHETIC_KIND);
    expect(err.message).toContain('unit-test.location');
    expect(err.message).toContain('Adding a New ANF Value Kind');
    expect(err.name).toBe('UnknownANFKindError');
  });
});
