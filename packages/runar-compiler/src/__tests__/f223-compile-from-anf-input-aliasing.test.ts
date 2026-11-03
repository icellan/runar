/**
 * F-223 (CX-BUG-109) — `compileFromANF` aliased its input with
 * `const anf: ANFProgram = program`, then wrote baked constructor values
 * directly onto the SAME property objects the caller's `program` points at
 * (`prop.initialValue = opts.constructorArgs[prop.name]`). No clone was made.
 *
 * Effect: a caller that parses/loads an ANF program once and calls
 * `compileFromANF` on it twice — e.g. to bake two different constructor
 * argument sets, or to bake once and later compile unbaked — sees:
 *   (a) its own `program` object permanently mutated after the call returns;
 *   (b) a LATER call that passes no (or different) `constructorArgs` silently
 *       inherit the EARLIER call's baked value instead of treating the
 *       property as unbaked, because the shared property object still carries
 *       the previous bake.
 *
 * What this proves:
 *   1. After two calls to `compileFromANF` on the same shared `ANFProgram`
 *      with different `constructorArgs`, the caller's object is unchanged —
 *      the baked `initialValue` never leaks onto the property the caller
 *      still holds a reference to.
 *   2. A later call on that same shared object with NO `constructorArgs`
 *      compiles exactly like a fresh, never-baked program (OP_0 placeholder
 *      for the unbaked readonly property), not like the earlier bake —
 *      i.e. output is independent of call order / history, not just of the
 *      input object's final shape.
 *
 * What this does NOT prove:
 *   - Anything about the Go/Rust/Python/Zig/Ruby/Java `--ir` entry points;
 *     those are covered (or found clean) in their own tiers' test suites.
 *   - That `compileFromANF`'s baking logic is otherwise correct — only that
 *     it no longer mutates a caller-owned structure.
 */

import { describe, it, expect } from 'vitest';
import { compileFromANF } from '../index.js';
import type { ANFProgram } from '../ir/index.js';

/** unlock() { assert(x) } — x is a readonly bigint property, unbaked. */
function programWithUnbakedX(): ANFProgram {
  return {
    contractName: 'Baked',
    properties: [{ name: 'x', type: 'bigint', readonly: true }],
    methods: [
      {
        name: 'unlock',
        isPublic: true,
        params: [],
        body: [
          { name: 't0', value: { kind: 'load_prop', name: 'x' } },
          { name: 't1', value: { kind: 'assert', value: 't0' } },
        ],
      },
    ],
  };
}

describe('F-223 compileFromANF: does not alias/mutate its input ANFProgram', () => {
  it('the caller\'s program object is unchanged after two bakes with different constructorArgs', () => {
    const shared = programWithUnbakedX();

    const r1 = compileFromANF(shared, { constructorArgs: { x: 1n } });
    const r2 = compileFromANF(shared, { constructorArgs: { x: 2n } });

    // The caller's own property must never have been written to.
    const xProp = shared.properties.find((p) => p.name === 'x');
    expect(xProp).toBeDefined();
    expect(xProp!.initialValue).toBeUndefined();

    // Each call must have baked its own value, independently of the other.
    expect(r1.scriptHex).toBe(compileFromANF(programWithUnbakedX(), { constructorArgs: { x: 1n } }).scriptHex);
    expect(r2.scriptHex).toBe(compileFromANF(programWithUnbakedX(), { constructorArgs: { x: 2n } }).scriptHex);
    expect(r1.scriptHex).not.toBe(r2.scriptHex);
  });

  it('a later call with no constructorArgs on the same shared object is not order-dependent', () => {
    const shared = programWithUnbakedX();

    // Bake x=1n once.
    compileFromANF(shared, { constructorArgs: { x: 1n } });

    // A later call on the SAME object with no constructorArgs must compile
    // exactly like a fresh, never-baked program (OP_0 placeholder) — it must
    // not inherit the earlier bake via a mutated shared property.
    const later = compileFromANF(shared);
    const freshUnbaked = compileFromANF(programWithUnbakedX());

    expect(later.scriptHex).toBe(freshUnbaked.scriptHex);
  });
});
