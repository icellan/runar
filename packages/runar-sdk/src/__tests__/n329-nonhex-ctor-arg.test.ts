/**
 * N-329: a ByteString-family constructor arg that is not an even-length hex
 * string must be refused at construction with a typed error. Before, it was
 * spliced into the locking script as raw text (a push header sized for the raw
 * bytes followed by non-hex characters) with no error.
 *
 * Proves: `new RunarContract` throws InvalidConstructorArgError for raw
 * (non-hex) Addr text, odd-length hex and a non-hex FixedArray<Addr, 2> leaf,
 * with the shared diagnostic; valid hex (either case, empty) is accepted and
 * getLockingScript() is hex-only.
 * Does NOT prove: width checks (a 3-byte Addr is accepted here) or on-chain
 * spendability.
 */
import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { InvalidConstructorArgError } from '../errors.js';
import type { RunarArtifact } from 'runar-ir-schema';

function makeArtifact(type: string, fixedArray?: { elementType: string; length: number; syntheticNames: string[] }): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'N329',
    asm: '',
    buildTimestamp: '2026-03-02T00:00:00.000Z',
    script: '00',
    abi: {
      constructor: { params: [{ name: 'owner', type, ...(fixedArray ? { fixedArray } : {}) }] },
      methods: [{ name: 'noop', params: [], isPublic: true }],
    },
    constructorSlots: [{ paramIndex: 0, byteOffset: 0 }],
  } as RunarArtifact;
}

describe('N-329 non-hex ByteString constructor arg', () => {
  const rawAddr = String.fromCharCode(...Array.from({ length: 20 }, (_, i) => 0x80 + i));
  for (const [label, type, arg] of [
    ['raw Addr bytes', 'Addr', rawAddr],
    ['odd-length hex', 'ByteString', 'abc'],
    ['non-hex text', 'PubKey', 'zz'],
  ] as const) {
    it(`refuses ${label}`, () => {
      expect(() => new RunarContract(makeArtifact(type), [arg])).toThrow(InvalidConstructorArgError);
      expect(() => new RunarContract(makeArtifact(type), [arg])).toThrow(
        /constructor arg 'owner' \(.*\) of N329 must be an even-length hex string/,
      );
    });
  }

  it('refuses a non-hex FixedArray<Addr, 2> leaf', () => {
    const a = makeArtifact('FixedArray<Addr, 2>', { elementType: 'Addr', length: 2, syntheticNames: ['owner__0', 'owner__1'] });
    expect(() => new RunarContract(a, [['aabb', 'not-hex!']])).toThrow(InvalidConstructorArgError);
  });

  for (const arg of ['9a1c78a5', '9A1C78A5', '']) {
    it(`accepts hex ${JSON.stringify(arg)}`, () => {
      const c = new RunarContract(makeArtifact('ByteString'), [arg]);
      expect(c.getLockingScript()).toMatch(/^([0-9a-fA-F]{2})*$/);
    });
  }
});
