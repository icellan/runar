import { describe, it, expect } from 'vitest';
import { ScriptVM } from '../vm/script-vm.js';
import { InputLimits, CanonicalJsonError } from 'runar-ir-schema';

describe('ScriptVM input size guards', () => {
  it('executeScript rejects scripts > MAX_SCRIPT_BYTES with CanonicalJsonError', () => {
    const vm = new ScriptVM();
    const overlimit = new Uint8Array(InputLimits.MAX_SCRIPT_BYTES + 1);
    try {
      vm.executeScript(overlimit);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('bytes');
      expect(cje.limit).toBe(InputLimits.MAX_SCRIPT_BYTES);
      expect(cje.actual).toBe(InputLimits.MAX_SCRIPT_BYTES + 1);
    }
  });

  it('execute rejects either script when over the byte cap', () => {
    const vm = new ScriptVM();
    const ok = new Uint8Array([0x51]); // OP_1
    const big = new Uint8Array(InputLimits.MAX_SCRIPT_BYTES + 1);
    expect(() => vm.execute(ok, big)).toThrow(CanonicalJsonError);
    expect(() => vm.execute(big, ok)).toThrow(CanonicalJsonError);
  });

  it('load (step mode) rejects scripts over the byte cap', () => {
    const vm = new ScriptVM();
    const big = new Uint8Array(InputLimits.MAX_SCRIPT_BYTES + 1);
    const ok = new Uint8Array([0x51]);
    expect(() => vm.load(big, ok)).toThrow(CanonicalJsonError);
    expect(() => vm.load(ok, big)).toThrow(CanonicalJsonError);
  });

  it('accepts a legitimately-sized script (well under cap)', () => {
    // Simple OP_1 script: empty unlock + single-push OP_1 lock => success.
    const vm = new ScriptVM();
    const result = vm.executeScript(new Uint8Array([0x51]));
    expect(result.success).toBe(true);
  });
});
