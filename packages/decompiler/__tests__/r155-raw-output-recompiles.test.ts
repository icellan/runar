import { describe, it, expect } from 'vitest';
import { emitRawScriptSource } from '../src/emit-ts.js';
import { compile } from 'runar-compiler';

/**
 * R-155 / CL-BUG-086 — the `--raw` output could not be recompiled by the
 * project that produced it.
 *
 * `emitRawScriptSource` emitted
 *
 *     import { SmartContract, asm } from 'runar-lang';
 *     export class _Recovered extends SmartContract {
 *       public unlock(): void { asm({ body: '...', ... }); }
 *     }
 *
 * and the compiler's own validator refuses exactly that: "'asm' is only
 * available in contracts extending UnsafeSmartContract". So the decompiler's
 * honest-bytes path produced source its own toolchain rejects — while the file
 * header promised "round-trip is byte-identical", which is true of the ANF path
 * and was never true of the SOURCE it printed.
 *
 * `UnsafeSmartContract` is precisely the base class `asm()` exists for. The
 * project's own `scripts/probe_minimal.ts` already got this right, which is how
 * the contrast was established.
 *
 * This test compiles the emitted source. A grep for the class name would pass
 * against any string containing it; only the compiler can say whether the
 * output is source.
 */

const SCRIPT = new Uint8Array([0x76, 0xa9, 0x14, ...new Array(20).fill(0xab), 0x88, 0xac]);

describe('R-155 the raw decompiler output is recompilable', () => {
  it('compiles through the real compiler', () => {
    const src = emitRawScriptSource(SCRIPT, { className: 'Recovered' });
    const result = compile(src, { fileName: 'Recovered.runar.ts' });
    expect(
      result.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message),
      'the decompiler emitted source its own compiler rejects',
    ).toEqual([]);
    expect(result.success).toBe(true);
  });

  it('extends UnsafeSmartContract — the base class asm() exists for', () => {
    const src = emitRawScriptSource(SCRIPT);
    expect(src).toMatch(/extends UnsafeSmartContract\b/);
    expect(src).not.toMatch(/extends SmartContract\b/);
  });

  it('imports the base class it extends', () => {
    const src = emitRawScriptSource(SCRIPT);
    expect(src).toMatch(/import \{[^}]*UnsafeSmartContract[^}]*\} from 'runar-lang'/);
  });

  it('the recompiled script is byte-identical to the input bytes', () => {
    const src = emitRawScriptSource(SCRIPT, { className: 'Recovered' });
    const result = compile(src, { fileName: 'Recovered.runar.ts' });
    const hex = Buffer.from(SCRIPT).toString('hex');
    expect(
      result.artifact?.script,
      'the point of the raw path is that the bytes survive; if they do not, ' +
        'the header promise is false in the other direction too',
    ).toContain(hex);
  });
});
