/**
 * N-073: a fixed-width ByteString-family constructor arg must have its
 * declared width (Addr/Ripemd160 20, Sha256 32, PubKey 33, Point/P256Point 64,
 * P384Point 96), with N-045's message. fromUtxo is unaffected: its internal
 * restore path skips the check.
 *
 * Proves: a 33-byte Sha256 and a 19-byte Addr (scalar and FixedArray leaf)
 * are refused with InvalidConstructorArgError carrying the N-045 wording;
 * correct widths are accepted; width-less types (ByteString) still take any
 * length; fromUtxo still restores a contract.
 * Does NOT prove: method-call or state value widths (N-045), on-chain
 * spendability, or that the restore bypass is unreachable by user input.
 */
import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { InvalidConstructorArgError } from '../errors.js';
import type { RunarArtifact } from 'runar-ir-schema';

function makeArtifact(type: string, fixedArray?: { elementType: string; length: number; syntheticNames: string[] }): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'N073',
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

const hexOf = (n: number) => 'ab'.repeat(n);

describe('N-073 fixed-width constructor arg', () => {
  it('refuses a 33-byte Sha256 with the N-045 message', () => {
    const make = () => new RunarContract(makeArtifact('Sha256'), [hexOf(33)]);
    expect(make).toThrow(InvalidConstructorArgError);
    expect(make).toThrow(/constructor arg 'owner' \(Sha256\).*must be exactly 32 bytes of hex, got 33 bytes/);
  });

  it('refuses a 19-byte Addr', () => {
    expect(() => new RunarContract(makeArtifact('Addr'), [hexOf(19)])).toThrow(InvalidConstructorArgError);
  });

  it('refuses a 19-byte Addr FixedArray leaf', () => {
    const fa = { elementType: 'Addr', length: 2, syntheticNames: ['owner__0', 'owner__1'] };
    expect(
      () => new RunarContract(makeArtifact('FixedArray<Addr, 2>', fa), [[hexOf(20), hexOf(19)]]),
    ).toThrow(InvalidConstructorArgError);
  });

  it.each([
    ['Addr', 20], ['Ripemd160', 20], ['Sha256', 32], ['PubKey', 33],
    ['Point', 64], ['P256Point', 64], ['P384Point', 96],
  ])('accepts a correct-width %s (%i bytes) and refuses one byte less', (type, n) => {
    expect(() => new RunarContract(makeArtifact(type), [hexOf(n)]).getLockingScript()).not.toThrow();
    expect(() => new RunarContract(makeArtifact(type), [hexOf(n - 1)])).toThrow(InvalidConstructorArgError);
  });

  it('still accepts any length for ByteString', () => {
    expect(() => new RunarContract(makeArtifact('ByteString'), [hexOf(3)])).not.toThrow();
  });

  it('fromUtxo still restores a contract', () => {
    const artifact = makeArtifact('Addr');
    const script = new RunarContract(artifact, [hexOf(20)]).getLockingScript();
    const c = RunarContract.fromUtxo(artifact, { txid: '00'.repeat(32), outputIndex: 0, satoshis: 1, script });
    expect(c.getLockingScript()).toBe(script);
  });
});
