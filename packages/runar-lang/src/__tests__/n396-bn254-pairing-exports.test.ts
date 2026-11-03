import { describe, it, expect } from 'vitest';
import * as lang from '../index.js';

// N-396: the BN254 pairing builtins the compilers lower (Go codegen, arity
// table in runar-compiler/src/ir/builtin-arity.ts) must be importable from
// 'runar-lang', or conformance/tests/bn254-pairing/Bn254Pairing.runar.ts fails
// `pnpm run conformance:typecheck`.
//
// Proves: each name is exported as a function whose declared parameter count
// equals the compilers' arity (5 / 27 / 20) and that calling it throws the
// standard "compile this contract" stub error.
// Does not prove: parameter types (that is `conformance:typecheck`, which
// compiles the fixture against the emitted .d.ts) or on-chain behaviour.
const ARITY: Record<string, number> = {
  bn254Pairing: 5,
  bn254MultiPairing3: 27,
  bn254MultiPairing4: 20,
};

describe('N-396 BN254 pairing builtins are exported by runar-lang', () => {
  for (const [name, arity] of Object.entries(ARITY)) {
    it(`${name} is exported with arity ${arity} and is a compiler stub`, () => {
      const fn = (lang as unknown as Record<string, unknown>)[name];
      expect(typeof fn).toBe('function');
      expect((fn as (...a: unknown[]) => unknown).length).toBe(arity);
      expect(() => (fn as () => unknown)()).toThrow(`${name}()`);
    });
  }
});
