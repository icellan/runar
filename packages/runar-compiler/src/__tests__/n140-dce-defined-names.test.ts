/**
 * N-140 — DCE liveness must consider the names a binding DEFINES, not only its
 * own `name`.
 *
 * ## The defect
 *
 * `filterLiveBindings` kept a binding iff
 * `refs.has(binding.name) || hasSideEffect(binding.value)`.
 *
 * An `if` that merges branch locals is a binding named `t<n>` carrying
 * `results: ['a','b']`, with both arms binding `a` and `b`. NOTHING ever
 * references `t<n>` — later code references `a` and `b`. When both arms are
 * pure `load_const`, `hasSideEffect` is false too, so the whole
 * `OP_IF … OP_ELSE … OP_ENDIF` was deleted and the merged locals kept their
 * pre-branch values. `assert(a + b > 0n)` then compiled to `0 + 0 > 0` and the
 * locking script could not be satisfied by any input.
 *
 * The defect was identical in all seven tiers, so cross-tier byte parity held
 * throughout — which is why the executable gate lives in
 * `conformance/dce/live-if.test.ts` and asserts SPENDABILITY rather than
 * agreement. These tests pin the rule itself, at the tier where it is defined.
 *
 * ## What these tests do NOT prove
 *
 * Nothing about the emitted hex, and nothing about the six ports. They are the
 * TypeScript predicate's unit-level record of a rule the conformance gate
 * measures end to end.
 */

import { describe, it, expect } from 'vitest';
import { eliminateDeadBindings } from '../optimizer/dce.js';
import type { ANFProgram, ANFBinding, ANFValue } from '../ir/index.js';

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

function konst(name: string, value: bigint): ANFBinding {
  return b(name, { kind: 'load_const', value });
}

function programWith(body: ANFBinding[]): ANFProgram {
  return {
    contractName: 'T',
    properties: [],
    methods: [{ name: 'm', params: [], body, isPublic: true }],
  };
}

function survivingNames(program: ANFProgram): string[] {
  const method = program.methods[0];
  if (method === undefined) throw new Error('DCE dropped the method itself');
  return method.body.map((x) => x.name);
}

/** `if (c) { a = 1; b = 2 } else { a = 3; b = 4 }` — declared results, pure arms. */
function mergingIf(name: string): ANFBinding {
  return b(name, {
    kind: 'if',
    cond: 'c',
    then: [konst('a', 1n), konst('b', 2n)],
    else: [konst('a', 3n), konst('b', 4n)],
    results: ['a', 'b'],
  });
}

describe('N-140: DCE liveness over defined names', () => {
  it('keeps a pure `if` whose declared results are referenced later', () => {
    const out = eliminateDeadBindings(
      programWith([
        konst('c', 1n),
        mergingIf('t9'),
        b('sum', { kind: 'bin_op', op: '+', left: 'a', right: 'b' }),
        b('chk', { kind: 'assert', value: 'sum' }),
      ]),
    );
    expect(
      survivingNames(out).includes('t9'),
      'DCE deleted a live `if`: nothing references `t9`, but `a` and `b` — the ' +
        'names it defines via `results` — are read by the assert below it. ' +
        'The merged locals then keep their pre-branch values and the locking ' +
        'script cannot be satisfied.',
    ).toBe(true);
  });

  it('keeps a pure `if` whose arm-bound name is referenced from outside', () => {
    // No `results` declared: liveness must still see the names the arms bind.
    const out = eliminateDeadBindings(
      programWith([
        konst('c', 1n),
        b('t9', {
          kind: 'if',
          cond: 'c',
          then: [konst('x', 1n)],
          else: [konst('x', 3n)],
        }),
        b('chk', { kind: 'assert', value: 'x' }),
      ]),
    );
    expect(survivingNames(out).includes('t9')).toBe(true);
  });

  it('still drops a dead `if` whose arms only reference each other', () => {
    // The negative control that stops the rule degenerating into "never delete
    // an `if`". `n1` reads `n0`, but both live inside the arm and nothing
    // outside reads either, so the node is genuinely dead.
    const out = eliminateDeadBindings(
      programWith([
        konst('c', 1n),
        b('t9', {
          kind: 'if',
          cond: 'c',
          then: [konst('n0', 1n), b('n1', { kind: 'bin_op', op: '+', left: 'n0', right: 'n0' })],
          else: [],
        }),
        konst('k', 1n),
        b('chk', { kind: 'assert', value: 'k' }),
      ]),
    );
    expect(
      survivingNames(out).includes('t9'),
      'a pure `if` referenced by nothing outside itself should still be eliminated',
    ).toBe(false);
  });

  it('still drops a dead `loop` whose body only references itself', () => {
    const out = eliminateDeadBindings(
      programWith([
        b('t9', {
          kind: 'loop',
          count: 2,
          body: [konst('n0', 1n), b('n1', { kind: 'bin_op', op: '+', left: 'n0', right: 'i' })],
          iterVar: 'i',
          start: 0n,
          step: 1,
        }),
        konst('k', 1n),
        b('chk', { kind: 'assert', value: 'k' }),
      ]),
    );
    expect(survivingNames(out).includes('t9')).toBe(false);
  });

  it('keeps a `loop` whose body-bound name is read after the loop', () => {
    const out = eliminateDeadBindings(
      programWith([
        b('t9', {
          kind: 'loop',
          count: 2,
          body: [konst('acc', 1n)],
          iterVar: 'i',
          start: 0n,
          step: 1,
        }),
        b('chk', { kind: 'assert', value: 'acc' }),
      ]),
    );
    expect(survivingNames(out).includes('t9')).toBe(true);
  });
});
