/**
 * N-330: a non-string ByteString-family constructor arg must either be encoded
 * as the raw bytes it is (Uint8Array / Buffer) or refused with
 * InvalidConstructorArgError. Before, encodeArg's fallback did String(v), so a
 * Uint8Array became "1,2,3" and null/undefined/a number were spliced in as text
 * or as a script number.
 *
 * Proves: Uint8Array/Buffer args (scalar and FixedArray leaf) yield the same
 * locking script as the equivalent hex string; null, undefined, number, bigint,
 * boolean and plain-object args are refused with the shared diagnostic.
 * Does NOT prove: width checks, method-call args, or on-chain spendability.
 */
import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { InvalidConstructorArgError } from '../errors.js';
import type { RunarArtifact } from 'runar-ir-schema';

function makeArtifact(type: string, fixedArray?: { elementType: string; length: number; syntheticNames: string[] }): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'N330',
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

describe('N-330 non-string ByteString constructor arg', () => {
  const bytes = [0x9a, 0x1c, 0x78, 0xa5];
  const hex = '9a1c78a5';

  it('encodes a Uint8Array as its raw bytes', () => {
    const viaBytes = new RunarContract(makeArtifact('ByteString'), [new Uint8Array(bytes)]).getLockingScript();
    const viaHex = new RunarContract(makeArtifact('ByteString'), [hex]).getLockingScript();
    expect(viaBytes).toBe(viaHex);
  });

  it('encodes a Buffer as its raw bytes', () => {
    const viaBuf = new RunarContract(makeArtifact('PubKey'), [Buffer.from(bytes)]).getLockingScript();
    const viaHex = new RunarContract(makeArtifact('PubKey'), [hex]).getLockingScript();
    expect(viaBuf).toBe(viaHex);
  });

  it('encodes a Uint8Array FixedArray<Addr, 2> leaf as its raw bytes', () => {
    const fa = { elementType: 'Addr', length: 2, syntheticNames: ['owner__0', 'owner__1'] };
    const a = makeArtifact('FixedArray<Addr, 2>', fa);
    const viaBytes = new RunarContract(a, [[new Uint8Array(bytes), hex]]).getLockingScript();
    const viaHex = new RunarContract(a, [[hex, hex]]).getLockingScript();
    expect(viaBytes).toBe(viaHex);
  });

  for (const [label, arg] of [
    ['null', null],
    ['undefined', undefined],
    ['number', 5],
    ['bigint', 5n],
    ['boolean', true],
    ['plain array of numbers', [1, 2, 3]],
    ['plain object', { a: 1 }],
  ] as const) {
    it(`refuses ${label}`, () => {
      expect(() => new RunarContract(makeArtifact('ByteString'), [arg])).toThrow(InvalidConstructorArgError);
      expect(() => new RunarContract(makeArtifact('ByteString'), [arg])).toThrow(
        /constructor arg 'owner' \(ByteString\) of N330 must be an even-length hex string/,
      );
    });
  }

  it('refuses a null FixedArray<Addr, 2> leaf', () => {
    const fa = { elementType: 'Addr', length: 2, syntheticNames: ['owner__0', 'owner__1'] };
    expect(() => new RunarContract(makeArtifact('FixedArray<Addr, 2>', fa), [[hex, null]])).toThrow(InvalidConstructorArgError);
  });
});
