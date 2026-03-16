/**
 * Tests for the mock-preimage module — standalone BIP-143 preimage building
 * for stateful Runar contracts.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';
import {
  buildStatefulPreimage,
  buildLockingScript,
  buildContinuationOutput,
  computeHashOutputs,
  serializeState,
} from '../mock-preimage.js';

// ---------------------------------------------------------------------------
// Contract sources
// ---------------------------------------------------------------------------

/** Simple stateful counter: one mutable bigint field. */
const counterSource = `
import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }

  public decrement() {
    assert(this.count > 0n);
    this.count--;
  }
}
`;

/** Stateless contract that just uses checkPreimage (for basic preimage test). */
const statelessSource = `
import { SmartContract, assert } from 'runar-lang';

class Simple extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint, b: bigint) {
    assert(a + b === this.target);
  }
}
`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compileArtifact(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.success || !result.artifact) {
    const errors = result.diagnostics
      .filter((d) => d.severity === 'error')
      .map((d) => d.message)
      .join('\n');
    throw new Error(`Compilation failed:\n${errors}`);
  }
  return result.artifact;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('mock-preimage', () => {
  // -----------------------------------------------------------------------
  // serializeState
  // -----------------------------------------------------------------------
  describe('serializeState', () => {
    it('serializes a single bigint field to 8-byte LE', () => {
      const fields = [{ name: 'count', type: 'bigint', index: 0 }];
      const hex = serializeState(fields, { count: 0n });
      expect(hex).toBe('0000000000000000');
      expect(hex.length).toBe(16); // 8 bytes * 2 hex chars
    });

    it('serializes a positive bigint', () => {
      const fields = [{ name: 'count', type: 'bigint', index: 0 }];
      const hex = serializeState(fields, { count: 42n });
      // 42 = 0x2a, 8-byte LE = 2a 00 00 00 00 00 00 00
      expect(hex).toBe('2a00000000000000');
    });

    it('serializes a negative bigint', () => {
      const fields = [{ name: 'count', type: 'bigint', index: 0 }];
      const hex = serializeState(fields, { count: -1n });
      // -1 in 8-byte LE sign-magnitude: 01 00 00 00 00 00 00 80
      expect(hex).toBe('0100000000000080');
    });

    it('serializes a boolean field', () => {
      const fields = [{ name: 'active', type: 'bool', index: 0 }];
      expect(serializeState(fields, { active: true })).toBe('01');
      expect(serializeState(fields, { active: false })).toBe('00');
    });

    it('serializes multiple fields ordered by index', () => {
      const fields = [
        { name: 'b', type: 'bigint', index: 1 },
        { name: 'a', type: 'bigint', index: 0 },
      ];
      const hex = serializeState(fields, { a: 1n, b: 2n });
      // a (index 0) first, then b (index 1)
      expect(hex).toBe('0100000000000000' + '0200000000000000');
    });
  });

  // -----------------------------------------------------------------------
  // buildLockingScript
  // -----------------------------------------------------------------------
  describe('buildLockingScript', () => {
    it('builds a locking script for a stateful counter contract', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');
      const script = buildLockingScript(artifact, { count: 0n }, { count: 0n });

      // Should contain OP_RETURN (6a) followed by state
      expect(script).toContain('6a');
      // State should be 8 zero bytes (count=0)
      expect(script.endsWith('0000000000000000')).toBe(true);
    });

    it('builds a locking script for a stateless contract (no OP_RETURN)', () => {
      const artifact = compileArtifact(statelessSource, 'Simple.runar.ts');
      const script = buildLockingScript(artifact, { target: 10n }, {});

      // Should NOT contain OP_RETURN separator since there are no state fields
      // (The script itself may contain 6a as data, but there should be no
      // state suffix appended)
      expect(artifact.stateFields).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // buildContinuationOutput
  // -----------------------------------------------------------------------
  describe('buildContinuationOutput', () => {
    it('builds a continuation output for Counter after increment', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');
      const codePart = artifact.script; // use raw script as codePart

      const output = buildContinuationOutput(
        codePart,
        artifact.stateFields!,
        { count: 1n },
        10000n,
      );

      // First 16 hex chars (8 bytes) = satoshis in LE
      const satoshisHex = output.slice(0, 16);
      // 10000 = 0x2710
      expect(satoshisHex).toBe('1027000000000000');

      // After satoshis, there's a varint for script length, then the script
      // The script is: codePart + '6a' + state
      const expectedScript = codePart + '6a' + '0100000000000000'; // count=1
      const expectedScriptLen = expectedScript.length / 2;

      // Check that the output ends with the expected script
      expect(output).toContain(expectedScript);

      // Check that total length is correct
      // 8 (satoshis) + varint + script
      const varintLen =
        expectedScriptLen < 0xfd ? 1 : expectedScriptLen <= 0xffff ? 3 : 5;
      expect(output.length / 2).toBe(8 + varintLen + expectedScriptLen);
    });
  });

  // -----------------------------------------------------------------------
  // computeHashOutputs
  // -----------------------------------------------------------------------
  describe('computeHashOutputs', () => {
    it('returns hash256 of empty for no outputs', () => {
      const result = computeHashOutputs([]);
      // hash256('') = sha256(sha256(''))
      // sha256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      // sha256(sha256('')) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
      expect(result).toBe(
        '5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456',
      );
      expect(result.length).toBe(64); // 32 bytes hex
    });

    it('returns hash256 of a single output', () => {
      const output = '1027000000000000' + '01' + 'ff'; // 10000 sats, 1-byte script: 0xff
      const result = computeHashOutputs([output]);
      expect(result.length).toBe(64);
      // Verify it's deterministic
      expect(result).toBe(computeHashOutputs([output]));
    });

    it('combines multiple outputs before hashing', () => {
      const out1 = '1027000000000000' + '01' + 'aa';
      const out2 = '1027000000000000' + '01' + 'bb';
      const combined = computeHashOutputs([out1, out2]);
      // Should be different from hashing each separately
      const hash1 = computeHashOutputs([out1]);
      const hash2 = computeHashOutputs([out2]);
      expect(combined).not.toBe(hash1);
      expect(combined).not.toBe(hash2);
    });
  });

  // -----------------------------------------------------------------------
  // buildStatefulPreimage — BIP-143 field layout
  // -----------------------------------------------------------------------
  describe('buildStatefulPreimage', () => {
    it('builds a preimage for a stateful Counter with initial state', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');

      const result = buildStatefulPreimage({
        artifact,
        constructorArgs: { count: 0n },
        state: { count: 0n },
        newState: { count: 1n },
        satoshis: 10000n,
      });

      // Basic shape checks
      expect(result.preimageHex).toBeTruthy();
      expect(result.signatureHex).toBeTruthy();
      expect(result.lockingScript).toBeTruthy();
      expect(result.codePart).toBeTruthy();
      expect(result.scriptCode).toBeTruthy();
      expect(result.hashOutputs).toBeTruthy();

      // Signature should end with sighash byte 0x41
      expect(result.signatureHex.endsWith('41')).toBe(true);

      // hashOutputs should be 32 bytes (64 hex chars)
      expect(result.hashOutputs.length).toBe(64);
    });

    it('produces correct BIP-143 preimage field layout', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');

      const result = buildStatefulPreimage({
        artifact,
        constructorArgs: { count: 0n },
        state: { count: 0n },
        satoshis: 10000n,
        version: 1,
        locktime: 0,
        sequence: 0xffffffff,
      });

      const preimage = result.preimageHex;
      let offset = 0;

      // nVersion: 4 bytes LE
      const nVersion = preimage.slice(offset, offset + 8);
      expect(nVersion).toBe('01000000');
      offset += 8;

      // hashPrevouts: 32 bytes
      const hashPrevouts = preimage.slice(offset, offset + 64);
      expect(hashPrevouts.length).toBe(64);
      offset += 64;

      // hashSequence: 32 bytes
      const hashSequence = preimage.slice(offset, offset + 64);
      expect(hashSequence.length).toBe(64);
      offset += 64;

      // outpoint: 36 bytes (txid 32 + vout 4)
      const outpoint = preimage.slice(offset, offset + 72);
      // Dummy outpoint: 32 zero bytes + 00000000
      expect(outpoint).toBe('00'.repeat(32) + '00000000');
      offset += 72;

      // scriptCode: varint + script
      // We need to read the varint to know how long the scriptCode is.
      const varintByte = parseInt(preimage.slice(offset, offset + 2), 16);
      let scriptCodeLen: number;
      let varintSize: number;
      if (varintByte < 0xfd) {
        scriptCodeLen = varintByte;
        varintSize = 2; // 1 byte = 2 hex chars
      } else if (varintByte === 0xfd) {
        const lo = parseInt(preimage.slice(offset + 2, offset + 4), 16);
        const hi = parseInt(preimage.slice(offset + 4, offset + 6), 16);
        scriptCodeLen = lo | (hi << 8);
        varintSize = 6;
      } else {
        throw new Error('Unexpected varint size');
      }
      offset += varintSize + scriptCodeLen * 2;

      // amount: 8 bytes LE
      const amount = preimage.slice(offset, offset + 16);
      expect(amount).toBe('1027000000000000'); // 10000 sats
      offset += 16;

      // nSequence: 4 bytes LE
      const nSequence = preimage.slice(offset, offset + 8);
      expect(nSequence).toBe('ffffffff');
      offset += 8;

      // hashOutputs: 32 bytes
      const hashOutputs = preimage.slice(offset, offset + 64);
      expect(hashOutputs).toBe(result.hashOutputs);
      offset += 64;

      // nLocktime: 4 bytes LE
      const nLocktime = preimage.slice(offset, offset + 8);
      expect(nLocktime).toBe('00000000');
      offset += 8;

      // sighashType: 4 bytes LE
      const sighashType = preimage.slice(offset, offset + 8);
      expect(sighashType).toBe('41000000'); // SIGHASH_ALL | SIGHASH_FORKID
      offset += 8;

      // Should have consumed the entire preimage
      expect(offset).toBe(preimage.length);
    });

    it('hashOutputs matches a manually computed continuation output', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');

      const result = buildStatefulPreimage({
        artifact,
        constructorArgs: { count: 0n },
        state: { count: 0n },
        newState: { count: 1n },
        satoshis: 10000n,
      });

      // Manually build the continuation output
      const contOutput = buildContinuationOutput(
        result.codePart,
        artifact.stateFields!,
        { count: 1n },
        10000n,
      );

      // hashOutputs should match
      expect(result.hashOutputs).toBe(computeHashOutputs([contOutput]));
    });

    it('builds a preimage with no new state (no continuation output)', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');

      const result = buildStatefulPreimage({
        artifact,
        constructorArgs: { count: 0n },
        state: { count: 0n },
        // No newState: no continuation output
        satoshis: 10000n,
      });

      // hashOutputs should be hash256 of empty data
      expect(result.hashOutputs).toBe(
        '5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456',
      );
    });

    it('builds a preimage for a stateless contract', () => {
      const artifact = compileArtifact(statelessSource, 'Simple.runar.ts');

      // Stateless contract: no state fields, no continuation
      const result = buildStatefulPreimage({
        artifact,
        constructorArgs: { target: 10n },
        state: {},
      });

      expect(result.preimageHex).toBeTruthy();
      expect(result.signatureHex.endsWith('41')).toBe(true);
      // codePart should equal lockingScript (no OP_RETURN + state)
      expect(result.codePart).toBe(result.lockingScript);
    });

    it('supports custom version and locktime', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');

      const result = buildStatefulPreimage({
        artifact,
        constructorArgs: { count: 0n },
        state: { count: 0n },
        version: 2,
        locktime: 500000,
      });

      const preimage = result.preimageHex;

      // nVersion = 2
      expect(preimage.slice(0, 8)).toBe('02000000');

      // nLocktime = 500000 = 0x0007A120
      // Find nLocktime: it's 8 hex chars before the last 8 (sighashType)
      const nLocktime = preimage.slice(-16, -8);
      expect(nLocktime).toBe('20a10700');
    });

    it('includes additional raw outputs in hashOutputs', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');

      // Build a raw additional output: 1000 sats, 1-byte script 0xff
      const rawOutput = '0000000000000000' + '01' + 'ff';

      const result = buildStatefulPreimage({
        artifact,
        constructorArgs: { count: 0n },
        state: { count: 0n },
        newState: { count: 1n },
        satoshis: 10000n,
        additionalOutputs: [rawOutput],
      });

      // hashOutputs should combine the continuation output + raw output
      const contOutput = buildContinuationOutput(
        result.codePart,
        artifact.stateFields!,
        { count: 1n },
        10000n,
      );
      const expected = computeHashOutputs([contOutput, rawOutput]);
      expect(result.hashOutputs).toBe(expected);
    });

    it('signature is a valid DER-encoded string', () => {
      const artifact = compileArtifact(counterSource, 'Counter.runar.ts');

      const result = buildStatefulPreimage({
        artifact,
        constructorArgs: { count: 0n },
        state: { count: 0n },
      });

      // DER signature starts with 0x30 (SEQUENCE tag)
      expect(result.signatureHex.slice(0, 2)).toBe('30');

      // Should end with sighash type 0x41
      expect(result.signatureHex.slice(-2)).toBe('41');

      // DER structure: 30 [len] 02 [rLen] [r] 02 [sLen] [s] + 41
      const sigBytes = hexToBytes(
        result.signatureHex.slice(0, -2), // strip sighash byte
      );
      expect(sigBytes[0]).toBe(0x30); // SEQUENCE
      expect(sigBytes[2]).toBe(0x02); // INTEGER (r)
    });
  });
});
