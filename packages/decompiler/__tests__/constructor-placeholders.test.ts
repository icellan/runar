/**
 * Constructor-placeholder recovery in the symexec lifter.
 *
 * Rúnar's emit pass writes an `OP_0` byte at every constructor-parameter
 * position whose value is supplied by the deployment SDK at deploy time.
 * The artifact records each placeholder as `{ paramIndex, byteOffset }`
 * in `constructorSlots`.
 *
 * Without `constructorSlots` plumbed through, the decompiler treats those
 * `OP_0` bytes as literal `0n` pushes. For many real-world shapes that
 * produces wrong source — the recovered comparison `value > 0n` doesn't
 * match the original `value > this.threshold` and re-compilation diverges.
 * With `constructorSlots` plumbed through, the symexec layer recovers the
 * placeholders as `load_prop` references to synthesized `this.prop<i>`
 * properties.
 *
 * Each test asserts:
 *   1. The decompile pipeline reports `recoveryPath: 'symexec'`.
 *   2. The recovered source declares matching `public readonly` properties.
 *   3. Re-compiling the recovered source produces byte-identical hex AND a
 *      matching `constructorSlots` entry (slot offsets must align).
 *
 * The probe contracts use shapes that are deliberately NOT in the
 * `templates-data.json` manifest and NOT caught by the opcode-pattern
 * recognizers — they need to reach the symexec layer to be exercised.
 */

import { describe, it, expect } from 'vitest';
import { hexToBytes } from 'runar-testing';
import { compile } from 'runar-compiler';
import { decompile } from '../src/index.js';

function compileSource(source: string, fileName = 'Probe.runar.ts') {
  const r = compile(source, { fileName });
  expect(r.success).toBe(true);
  expect(r.scriptHex).toBeDefined();
  expect(r.artifact).toBeDefined();
  return r;
}

describe('symexec — constructor placeholder recovery', () => {
  it('without constructorSlots, OP_0 placeholders are treated as literal 0n', () => {
    // Same probe as the next case; here we OMIT constructorSlots. The
    // symexec layer interprets OP_0 as `load_const 0n`, producing a
    // recovered source that compares `value > 0n` instead of
    // `value > this.threshold`. Re-compilation either lands at a different
    // recovery path (template/raw_script) or diverges in bytes — but
    // crucially, the recovered source does NOT contain `this.prop0`.
    const source = `
      import { SmartContract, assert } from 'runar-lang';
      class Threshold extends SmartContract {
        readonly threshold: bigint;
        constructor(threshold: bigint) { super(threshold); this.threshold = threshold; }
        public unlock(value: bigint) {
          assert(value > this.threshold);
        }
      }
    `;
    const r = compileSource(source);
    const dec = decompile(hexToBytes(r.scriptHex!));
    // Without slot info, the rendered source cannot reference a property.
    expect(dec.source).not.toContain('this.prop0');
  });

  it('recovers a single bigint placeholder via this.prop0 and round-trips byte-identically', () => {
    const source = `
      import { SmartContract, assert } from 'runar-lang';
      class Threshold extends SmartContract {
        readonly threshold: bigint;
        constructor(threshold: bigint) { super(threshold); this.threshold = threshold; }
        public unlock(value: bigint) {
          assert(value > this.threshold);
        }
      }
    `;
    const r = compileSource(source);
    expect(r.artifact!.constructorSlots).toEqual([{ paramIndex: 0, byteOffset: 0 }]);

    const dec = decompile(hexToBytes(r.scriptHex!), {
      constructorSlots: r.artifact!.constructorSlots,
    });
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.ok).toBe(true);

    // Source must declare the recovered property and reference it.
    expect(dec.source).toContain('readonly prop0:');
    expect(dec.source).toContain('this.prop0');

    // Re-compile and confirm byte-identity AND slot alignment.
    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
    expect(recompiled.artifact!.constructorSlots).toEqual(r.artifact!.constructorSlots);
  });

  it('recovers two placeholders at independent byte offsets via the full symexec pipeline', () => {
    // Two placeholders, slots at offsets 1 and 4 (after the OP_DUP +
    // OP_VERIFY interleave). The post-lift fixups (`replicateMultiUseLoads`
    // + `reorderConsumerOperands`) reshape the ANF so it matches what
    // source-compile produces — one `load_param value` binding per
    // source reference, in left-to-right operand order. The stack-lower
    // then picks the DUP-first layout (`OP_DUP <prop> OP_GREATERTHAN`),
    // re-emitting byte-identical bytes. Without those fixups the lifter's
    // shared-SSA-name ANF causes the lower to emit OP_OVER / OP_SWAP and
    // diverge — verified by the unfixed-output history of this test.
    const source = `
      import { SmartContract, assert } from 'runar-lang';
      class Range extends SmartContract {
        readonly lo: bigint;
        readonly hi: bigint;
        constructor(lo: bigint, hi: bigint) {
          super(lo, hi);
          this.lo = lo;
          this.hi = hi;
        }
        public unlock(value: bigint) {
          assert(value > this.lo);
          assert(value < this.hi);
        }
      }
    `;
    const r = compileSource(source);
    expect(r.artifact!.constructorSlots).toEqual([
      { paramIndex: 0, byteOffset: 1 },
      { paramIndex: 1, byteOffset: 4 },
    ]);

    const dec = decompile(hexToBytes(r.scriptHex!), {
      constructorSlots: r.artifact!.constructorSlots,
    });
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.ok).toBe(true);

    expect(dec.source).toContain('readonly prop0:');
    expect(dec.source).toContain('readonly prop1:');
    expect(dec.source).toContain('this.prop0');
    expect(dec.source).toContain('this.prop1');

    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
    expect(recompiled.artifact!.constructorSlots).toEqual(r.artifact!.constructorSlots);
  });

  it('contract with no placeholders does not synthesize spurious properties', () => {
    // Sanity guard: a contract with zero constructor placeholders must
    // recover with a plain `constructor()` and no `prop0`. This ensures
    // the property-emission path is gated on actual slot usage and not
    // accidentally triggered by zero-arity OP_0 emissions used for other
    // purposes (e.g. the empty-bytes literal).
    const source = `
      import { SmartContract, assert } from 'runar-lang';
      class Always extends SmartContract {
        constructor() { super(); }
        public unlock(value: bigint) {
          assert(value > 0n);
        }
      }
    `;
    const r = compileSource(source);
    // The artifact may omit constructorSlots entirely when there are none.
    expect(r.artifact!.constructorSlots ?? []).toEqual([]);

    const dec = decompile(hexToBytes(r.scriptHex!), {
      constructorSlots: r.artifact!.constructorSlots,
    });
    expect(dec.ok).toBe(true);
    expect(dec.source).not.toContain('prop0');
    expect(dec.source).toContain('constructor()');
  });
});
