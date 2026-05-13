/**
 * Multi-method symexec recovery.
 *
 * The dispatch recognizer (`splitMethods`) already isolates each public
 * method's opcode stream by detecting the asymmetric preamble emitted by
 * `emitMethodDispatch`. This suite verifies that `liftMultiMethod` runs
 * the straight-line symbolic lifter over each per-method stream and
 * stitches the recovered methods into a single `ANFProgram` that
 * re-compiles byte-identically.
 *
 * Key invariants exercised:
 *
 *   - 2-method contracts (the smallest non-trivial dispatch shape)
 *     round-trip via `recoveryPath: 'symexec'`.
 *   - 3-method contracts exercise the terminal preamble form
 *     (`<push N-1> OP_NUMEQUALVERIFY` for the last method, OP_NUMEQUAL /
 *     OP_IF / OP_ELSE chain for methods 0..N-2 with the appropriate
 *     trailing OP_ENDIFs).
 *   - `constructorSlots` plumbing crosses method boundaries: a property
 *     referenced in multiple methods recovers as a SINGLE `readonly propN`
 *     declaration and the constructor parameter list aligns with the
 *     original artifact.
 *   - Partial failure aborts the WHOLE pipeline to raw_script — never
 *     emit a half-recovered source where some methods are real TS and
 *     others are `raw_script` ANF, because that would shift the dispatch
 *     index ABI.
 */

import { describe, it, expect } from 'vitest';
import { hexToBytes } from 'runar-testing';
import { compile } from 'runar-compiler';
import { decompile, splitMethods, disassemble } from '../src/index.js';

function compileSource(source: string, fileName = 'Probe.runar.ts') {
  const r = compile(source, { fileName });
  expect(r.success).toBe(true);
  expect(r.scriptHex).toBeDefined();
  expect(r.artifact).toBeDefined();
  return r;
}

describe('symexec — multi-method dispatch', () => {
  it('2-method stateless contract round-trips byte-identically via symexec', () => {
    // Simplest non-trivial multi-method shape: two stateless public
    // methods, each a single bigint param + arithmetic assert. The
    // dispatch preamble emitted by the compiler:
    //   OP_DUP OP_0 OP_NUMEQUAL OP_IF OP_DROP <body_0> OP_ELSE
    //   OP_1 OP_NUMEQUALVERIFY <body_1>
    //   OP_ENDIF
    const source = `
      import { SmartContract, assert } from 'runar-lang';
      class TwoOps extends SmartContract {
        constructor() { super(); }
        public addOne(value: bigint): void {
          assert(value + 1n > 0n);
        }
        public mulTwo(value: bigint): void {
          assert(value * 2n > 0n);
        }
      }
    `;
    const r = compileSource(source);
    const bytes = hexToBytes(r.scriptHex!);

    // Sanity-check the dispatch recognizer saw 2 methods.
    const split = splitMethods(disassemble(bytes));
    expect(split.methodCount).toBe(2);

    const dec = decompile(bytes);
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).toBe('symexec');

    // Both methods must appear in the recovered source.
    expect(dec.source).toContain('public _method0');
    expect(dec.source).toContain('public _method1');

    // Re-compile and confirm byte-identity.
    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
  });

  it('3-method stateless contract round-trips byte-identically (asymmetric terminal preamble)', () => {
    // The terminal preamble uses OP_NUMEQUALVERIFY instead of
    // OP_NUMEQUAL/OP_IF, so we need a contract with at least 3 methods
    // for the recognizer to traverse both forms (continuation + terminal).
    const source = `
      import { SmartContract, assert } from 'runar-lang';
      class ThreeOps extends SmartContract {
        constructor() { super(); }
        public op0(a: bigint): void { assert(a + 1n > 0n); }
        public op1(a: bigint): void { assert(a + 2n > 0n); }
        public op2(a: bigint): void { assert(a + 3n > 0n); }
      }
    `;
    const r = compileSource(source);
    const bytes = hexToBytes(r.scriptHex!);

    const split = splitMethods(disassemble(bytes));
    expect(split.methodCount).toBe(3);

    const dec = decompile(bytes);
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).toBe('symexec');

    expect(dec.source).toContain('public _method0');
    expect(dec.source).toContain('public _method1');
    expect(dec.source).toContain('public _method2');

    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
  });

  it('multi-method + constructor placeholder unifies into a single property declaration', () => {
    // Both methods reference `this.threshold` — the lifter should
    // synthesize ONE `readonly prop0: bigint` declaration on the
    // contract, and the constructor parameter list must align with the
    // original artifact's `constructorSlots[].paramIndex`.
    const source = `
      import { SmartContract, assert } from 'runar-lang';
      class GatedTwo extends SmartContract {
        readonly threshold: bigint;
        constructor(threshold: bigint) {
          super(threshold);
          this.threshold = threshold;
        }
        public over(value: bigint): void {
          assert(value > this.threshold);
        }
        public under(value: bigint): void {
          assert(value < this.threshold);
        }
      }
    `;
    const r = compileSource(source);
    const slots = r.artifact!.constructorSlots ?? [];
    // Sanity: the source compiler stamped at least one placeholder per
    // reference to this.threshold (i.e. one per method using it).
    expect(slots.length).toBeGreaterThanOrEqual(2);

    const bytes = hexToBytes(r.scriptHex!);
    const split = splitMethods(disassemble(bytes));
    expect(split.methodCount).toBe(2);

    const dec = decompile(bytes, { constructorSlots: slots });
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).toBe('symexec');

    // Exactly ONE declaration despite both methods referencing the prop —
    // the merge in `liftMultiMethod` collapses duplicate `propN` entries
    // by name, otherwise the class body would carry two identical fields
    // and the parser would reject the source.
    const propMatches = dec.source.match(/readonly prop0\s*:/g) ?? [];
    expect(propMatches.length).toBe(1);
    // Both methods reference it via `this.prop0`.
    expect(dec.source).toContain('this.prop0');

    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(r.scriptHex);
    expect(recompiled.artifact!.constructorSlots).toEqual(slots);
  });

  it('one-method-fails aborts the whole recovery to raw_script (no partial recovery)', () => {
    // The first method is a clean arithmetic assert (would lift fine on
    // its own). The second method contains the OP_NOTIF idiom, which the
    // lifter refuses outright. The whole pipeline MUST fall through to
    // raw_script — partial recovery is unsafe because emitting some
    // methods as recovered TS and others wrapped in a raw_script ANF
    // node would shift the dispatch preamble's method indices and break
    // the ABI.
    //
    // We construct the bytes by hand. Dispatch preamble shape for N=2:
    //   OP_DUP OP_0 OP_NUMEQUAL OP_IF OP_DROP <body0> OP_ELSE
    //   OP_1 OP_NUMEQUALVERIFY <body1>
    //   OP_ENDIF
    //
    // body0 = OP_1ADD OP_0 OP_GREATERTHAN  (lifts cleanly to (a+1n)>0n)
    //   bytes: 8b 00 a0
    // body1 = OP_NOTIF OP_1 OP_ENDIF        (uses OP_NOTIF — refused)
    //   bytes: 64 51 68
    //
    // Full hex:
    //   76 00 9c 63 75 8b 00 a0 67   <- preamble + body0 + OP_ELSE
    //   51 9d 64 51 68                <- terminal preamble + body1
    //   68                            <- closing OP_ENDIF
    const hex = '76009c63758b00a067519d64516868';
    const bytes = hexToBytes(hex);

    // Sanity: dispatch recognizer must see 2 methods.
    const split = splitMethods(disassemble(bytes));
    expect(split.methodCount).toBe(2);

    const dec = decompile(bytes);
    // The crucial assertion — even though method 0 would lift fine, the
    // whole script must fall through to raw_script because method 1's
    // OP_NOTIF aborts the lifter.
    expect(dec.recoveryPath).toBe('raw_script');
    // Recovered source must NOT carry an `_method0` / `_method1` from
    // symexec — raw_script emits an `asm({...})` envelope instead.
    expect(dec.source).not.toContain('public _method0');
    expect(dec.source).not.toContain('public _method1');
  });
});
