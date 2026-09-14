/**
 * Stack lowering across unrolled for-loops — outer-scope refs (method
 * params, pre-loop consts) must survive loop unrolling:
 *
 *  (a) a const defined before a loop and referenced inside it (including
 *      only inside a nested if-branch) failed compilation with
 *      "Value 'X' not found on stack" — the first iteration consumed it;
 *  (b) worse, a method PARAM referenced after an unrolled loop whose body
 *      also references it was silently lowered to an empty push (OP_0):
 *      compilation succeeded, the env-based interpreter passed, but the
 *      emitted Script failed at runtime (silent interpreter<->Script
 *      divergence).
 *
 * The fix: lowerLoop collects outer refs deeply (nested branches included)
 * and protects them in non-final iterations, and in the final iteration
 * whenever the enclosing scope still references them after the loop. The
 * old silent OP_0 fallbacks are now hard errors.
 */

import { describe, it, expect } from 'vitest';
import { compile, compileFromANF } from '../index.js';
import type { ANFProgram } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/** V003 repro: multi-input tx walk — param `data` used inside AND after the loop. */
const LOOP_WALK_SOURCE = `
import { SmartContract, assert, substr, cat, bin2num } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class LoopWalk extends SmartContract {
  readonly pad00: ByteString = "00" as ByteString;

  constructor() {
    super();
  }

  public walk(data: ByteString) {
    let off = 5n;
    for (let i = 0n; i < 3n; i++) {
      if (i < bin2num(cat(substr(data, 4n, 1n), this.pad00))) {
        const sl = bin2num(cat(substr(data, off + 36n, 1n), this.pad00));
        assert(sl < 253n);
        off = off + 36n + 1n + sl + 4n;
      }
    }
    const tail = bin2num(cat(substr(data, off, 1n), this.pad00));
    assert(tail === 7n);
  }
}
`;

/** Symptom (a): const defined before the loop, referenced inside it. */
const CONST_BEFORE_LOOP_SOURCE = `
import { SmartContract, assert, substr, cat, bin2num } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class ConstLoop extends SmartContract {
  readonly pad00: ByteString = "00" as ByteString;

  constructor() {
    super();
  }

  public probe(data: ByteString) {
    const base = 5n;
    let acc = 0n;
    for (let i = 0n; i < 3n; i++) {
      const b = bin2num(cat(substr(data, base + i, 1n), this.pad00));
      acc = acc + b;
    }
    assert(acc === 6n);
  }
}
`;

/**
 * A loop-carried local REASSIGNED and then READ AGAIN in the same iteration.
 * The rebinding shadows the incoming slot under the same name; the later read
 * was its last body use, so it consumed the UPDATED value and left the dead
 * incoming one for the next iteration to resolve. `wacc` came out as `step*N`
 * instead of `step*N*(N+1)/2` — silently in a stateless contract, and as a
 * permanently unspendable UTXO in a stateful one. Real-VM proof:
 * packages/runar-testing/src/__tests__/loop-carried-local-read-after-reassign-vm.test.ts
 */
const CARRIED_REBIND_SOURCE = `import { SmartContract, assert } from 'runar-lang';

class LoopCarriedRebind extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    let wacc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + step;
      wacc = wacc + acc;
    }
    assert(wacc === this.expected);
  }
}
`;

/**
 * Control: the same loop with a single self-accumulating carrier — no read
 * after the rebinding. Its bytes must NOT move, or the carried-rebind fix has
 * been written too wide and every shipped `BoundedLoop`-shaped contract pays.
 * R-186 / R-292 re-stamped this pin on 2026-09-14: the accumulator body leaves
 * the carried local on top, so the iteration variable sat one slot down and
 * `lowerLoop`'s `depth == 0` cleanup never fired. The control still says what it
 * was written to say about the carried-rebind fix; it no longer pins the bytes
 * that predate it.
 */
const PLAIN_ACCUMULATOR_SOURCE = `import { SmartContract, assert } from 'runar-lang';

class LoopPlainAccumulator extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + step;
    }
    assert(acc === this.expected);
  }
}
`;

/**
 * The same cross-read one loop deeper. The predicate keys on the body's
 * TOP-LEVEL binding names, and at the OUTER level `acc` is bound only inside
 * the nested loop — so it was neither an outer ref nor a carried rebind, and
 * every outer iteration restarted from the slot the previous one left behind.
 * `wacc` came out 24 where the source says 30 (step = 3). Real-VM proof:
 * packages/runar-testing/src/__tests__/nested-loop-carried-local-vm.test.ts
 */
const NESTED_CARRIED_REBIND_SOURCE = `import { SmartContract, assert } from 'runar-lang';

class LoopNestedCarriedRebind extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    let wacc = 0n;
    for (let i = 0n; i < 2n; i++) {
      for (let j = 0n; j < 2n; j++) {
        acc = acc + step;
        wacc = wacc + acc;
      }
    }
    assert(wacc === this.expected);
  }
}
`;

/**
 * Control: NESTED loops with a single self-accumulating carrier. The flatten
 * step fires here (the body does contain a nested loop) but the predicate
 * still says "not carried", so the bytes must NOT move — that is what keeps
 * nesting itself from costing anything.
 * R-186 / R-292 re-stamped this pin on 2026-09-14 as well. Nesting still costs
 * nothing — the single-level accumulator moved by exactly the same change.
 */
const NESTED_PLAIN_ACCUMULATOR_SOURCE = `import { SmartContract, assert } from 'runar-lang';

class LoopNestedPlainAccumulator extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      for (let j = 0n; j < 2n; j++) {
        acc = acc + step;
      }
    }
    assert(acc === this.expected);
  }
}
`;

/** Byte-identical across all seven compiler tiers (fold-OFF). */
const CARRIED_REBIND_HEX =
  '000000537953797c937b78937b7551547a53797c937b7c9377009c7777';
const PLAIN_ACCUMULATOR_HEX = '000052797b7c9377517b7b7c9377009c';
const NESTED_CARRIED_REBIND_HEX =
  '00000000547954797c93537a78937b7551557953797c937b78937b75537a755100567954' +
  '797c93537a78937b7551577a53797c937b7c93777b75009c77777777';
const NESTED_PLAIN_ACCUMULATOR_HEX =
  '0000005379537a7c93775153797b7c93777751005379537a7c937751537a7b7c937777009c';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('stack lowering: outer refs across unrolled loops', () => {
  it('param referenced after a loop is not lowered to an empty push', () => {
    const result = compile(LOOP_WALK_SOURCE, { fileName: 'LoopWalk.runar.ts' });
    expect(result.success).toBe(true);

    // The post-loop code (after the last OP_ENDIF) reads `data` via
    // substr(data, off, 1n). With the bug, `data` was emitted as OP_0
    // right after the final OP_ENDIF; fixed code brings the real param up.
    const asm = result.scriptAsm!;
    const postLoop = asm.slice(asm.lastIndexOf('OP_ENDIF'));
    expect(postLoop).not.toContain('OP_0');
  });

  it('const defined before a loop and referenced inside compiles', () => {
    const result = compile(CONST_BEFORE_LOOP_SOURCE, {
      fileName: 'ConstLoop.runar.ts',
    });
    // Previously: "Value 'base' not found on stack (...)"
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBeDefined();
  });

  it('a load_param that cannot be satisfied is a loud error, not OP_0', () => {
    // Hand-written ANF referencing a parameter the method does not have —
    // the old code silently emitted OP_0 here.
    const program: ANFProgram = {
      contractName: 'Broken',
      properties: [],
      methods: [
        {
          name: 'run',
          isPublic: true,
          params: [{ name: 'x', type: 'bigint' }],
          body: [
            { name: 't0', value: { kind: 'load_param', name: 'ghost' } },
            { name: 't1', value: { kind: 'assert', value: 't0' } },
          ],
        },
      ],
    };

    expect(() => compileFromANF(program)).toThrow(
      /Refusing to emit a silent OP_0/,
    );
  });

  it('a local reassigned then read again in the same iteration survives it', () => {
    const result = compile(CARRIED_REBIND_SOURCE, {
      fileName: 'LoopCarriedRebind.runar.ts',
      disableConstantFolding: true,
    });
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBe(CARRIED_REBIND_HEX);
  });

  it('a plain accumulator loop is untouched by the carried-rebind fix', () => {
    const result = compile(PLAIN_ACCUMULATOR_SOURCE, {
      fileName: 'LoopPlainAccumulator.runar.ts',
      disableConstantFolding: true,
    });
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBe(PLAIN_ACCUMULATOR_HEX);
  });

  it('the same cross-read inside a NESTED loop survives it too', () => {
    const result = compile(NESTED_CARRIED_REBIND_SOURCE, {
      fileName: 'LoopNestedCarriedRebind.runar.ts',
      disableConstantFolding: true,
    });
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBe(NESTED_CARRIED_REBIND_HEX);
  });

  it('a nested plain accumulator is untouched by the nested fix', () => {
    const result = compile(NESTED_PLAIN_ACCUMULATOR_SOURCE, {
      fileName: 'LoopNestedPlainAccumulator.runar.ts',
      disableConstantFolding: true,
    });
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBe(NESTED_PLAIN_ACCUMULATOR_HEX);
  });
});
