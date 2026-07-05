import { describe, it, expect } from 'vitest';
import { reduceAnfProgram } from '../reduce.js';

// Uses the REAL ANF program shape the `anf-differential.ts` generator emits:
//   - method bindings live in `method.body` (NOT `method.bindings`)
//   - each binding is `{ name, value }` (bindings are keyed by `name`, NOT `id`)
//   - `assert` references its condition via `value` (NOT `ref`)
//   - `load_const` carries a bare `value: bigint | boolean` (NO `constType`)
//   - `bin_op`/`unary_op`/`call`/`array_literal`/`update_prop`/`assert`
//     reference prior bindings by their `name`
//
// `t2` and `t4` below are dead `load_const`s (nothing references them); the
// reducer should delete them while keeping the assert + its dependency chain
// (t5 -> t3 -> {t0, t1}) intact.
const PROG = {
  contractName: 'Big',
  properties: [] as unknown[],
  methods: [
    {
      name: 'spend',
      isPublic: true,
      params: [{ name: 'a', type: 'bigint' }],
      body: [
        { name: 't0', value: { kind: 'load_param', name: 'a' } },
        { name: 't1', value: { kind: 'load_const', value: 1n } },
        { name: 't2', value: { kind: 'load_const', value: 2n } }, // dead
        { name: 't3', value: { kind: 'bin_op', op: '+', left: 't0', right: 't1' } },
        { name: 't4', value: { kind: 'load_const', value: 3n } }, // dead
        { name: 't5', value: { kind: 'assert', value: 't3' } },
      ],
    },
  ],
};

// Collect the binding names a value references (so we can assert the reduced
// program has no dangling references).
function refsOf(value: any): string[] {
  switch (value.kind) {
    case 'bin_op':
      return [value.left, value.right];
    case 'unary_op':
      return [value.operand];
    case 'call':
      return value.args ?? [];
    case 'array_literal':
      return value.elements ?? [];
    case 'assert':
      return [value.value];
    case 'update_prop':
      return [value.value];
    default:
      return []; // load_param / load_prop / load_const reference no bindings
  }
}

describe('reduceAnfProgram (delta debugging)', () => {
  it('shrinks to a minimal program still satisfying the predicate', () => {
    // "interesting" = the program still has an assert binding.
    const interesting = (p: any) =>
      p.methods[0].body.some((b: any) => b.value.kind === 'assert');

    const reduced = reduceAnfProgram(PROG as never, interesting);
    const kinds = reduced.methods[0].body.map((b: any) => b.value.kind);

    // Dead consts (t2, t4) removed; assert + its dependencies retained.
    expect(kinds).toContain('assert');
    expect(reduced.methods[0].body.length).toBeLessThan(PROG.methods[0].body.length);
  });

  it('never introduces a dangling binding reference (well-formedness)', () => {
    const interesting = (p: any) =>
      p.methods[0].body.some((b: any) => b.value.kind === 'assert');

    const reduced = reduceAnfProgram(PROG as never, interesting);

    for (const method of reduced.methods) {
      const defined = new Set(method.body.map((b: any) => b.name));
      for (const b of method.body) {
        for (const ref of refsOf(b.value)) {
          expect(defined.has(ref), `binding ${b.name} references missing ${ref}`).toBe(true);
        }
      }
    }
  });

  it('does not mutate the input program', () => {
    const before = JSON.stringify(PROG, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    const interesting = (p: any) =>
      p.methods[0].body.some((b: any) => b.value.kind === 'assert');
    reduceAnfProgram(PROG as never, interesting);
    const after = JSON.stringify(PROG, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    expect(after).toBe(before);
  });
});
