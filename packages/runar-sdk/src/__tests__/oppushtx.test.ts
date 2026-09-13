import { describe, it, expect } from 'vitest';
import { Transaction, Script, BigNumber } from '@bsv/sdk';
import { computeOpPushTx } from '../oppushtx.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CURVE_ORDER = new BigNumber(
  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
  16,
);
const HALF_N = CURVE_ORDER.div(new BigNumber(2));

function makeTx(opts?: {
  sourceTXID?: string;
  numInputs?: number;
  lockingScriptHex?: string;
}): Transaction {
  const tx = new Transaction();
  tx.version = 1;
  const numInputs = opts?.numInputs ?? 1;
  for (let i = 0; i < numInputs; i++) {
    tx.addInput({
      sourceTXID: opts?.sourceTXID ?? 'aa'.repeat(32),
      sourceOutputIndex: i,
      sequence: 0xffffffff,
      unlockingScript: new Script(),
    });
  }
  tx.addOutput({
    satoshis: 10000,
    lockingScript: Script.fromHex(
      opts?.lockingScriptHex ?? '76a914' + '00'.repeat(20) + '88ac',
    ),
  });
  tx.lockTime = 0;
  return tx;
}

const SAMPLE_SUBSCRIPT = '76a914' + '00'.repeat(20) + '88ac';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('computeOpPushTx', () => {
  // -------------------------------------------------------------------------
  // 1. Basic computation
  // -------------------------------------------------------------------------
  describe('basic computation', () => {
    it('produces a valid DER signature ending with SIGHASH_ALL_FORKID (0x41)', () => {
      const tx = makeTx();
      const { sigHex, preimageHex } = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000);

      // DER sequence tag
      expect(sigHex.startsWith('30')).toBe(true);

      // Ends with sighash flag 0x41
      expect(sigHex.slice(-2)).toBe('41');

      // preimageHex is valid hex with even length
      expect(preimageHex.length % 2).toBe(0);
      expect(/^[0-9a-f]+$/i.test(preimageHex)).toBe(true);
    });

    it('is deterministic — same inputs produce identical output', () => {
      const tx = makeTx();
      const r1 = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000);
      const r2 = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000);
      expect(r1.sigHex).toBe(r2.sigHex);
      expect(r1.preimageHex).toBe(r2.preimageHex);
    });
  });

  // -------------------------------------------------------------------------
  // 2. Transaction from hex string
  // -------------------------------------------------------------------------
  describe('transaction from hex string', () => {
    it('accepts a hex string and produces the same result as a Transaction object', () => {
      const tx = makeTx();
      const hex = tx.toHex();
      const fromObj = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000);
      const fromHex = computeOpPushTx(hex, 0, SAMPLE_SUBSCRIPT, 10000);
      expect(fromHex.sigHex).toBe(fromObj.sigHex);
      expect(fromHex.preimageHex).toBe(fromObj.preimageHex);
    });
  });

  // -------------------------------------------------------------------------
  // 3. codeSeparatorIndex truncates the scriptCode
  // -------------------------------------------------------------------------
  describe('codeSeparatorIndex', () => {
    it('produces a different preimage when codeSeparatorIndex is provided', () => {
      const tx = makeTx();
      const without = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000);
      const withSep = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000, 2);
      expect(withSep.preimageHex).not.toBe(without.preimageHex);
      expect(withSep.sigHex).not.toBe(without.sigHex);
    });
  });

  // -------------------------------------------------------------------------
  // 4. codeSeparatorIndex at position 0
  // -------------------------------------------------------------------------
  describe('codeSeparatorIndex at position 0', () => {
    it('uses the full subscript minus the first byte as scriptCode', () => {
      const tx = makeTx();
      // With codeSeparatorIndex=0, scriptCode = subscript.slice(1*2) = subscript.slice(2)
      // i.e., chop the first byte off the subscript
      const trimmedSubscript = SAMPLE_SUBSCRIPT.slice(2);
      const withSep0 = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000, 0);
      const withTrimmed = computeOpPushTx(tx, 0, trimmedSubscript, 10000);
      // Both should produce the same preimage since the scriptCode is the same
      expect(withSep0.preimageHex).toBe(withTrimmed.preimageHex);
      expect(withSep0.sigHex).toBe(withTrimmed.sigHex);
    });
  });

  // -------------------------------------------------------------------------
  // 5. DER signature structure
  // -------------------------------------------------------------------------
  describe('DER signature structure', () => {
    it('has a well-formed DER encoding', () => {
      const tx = makeTx();
      const { sigHex } = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000);

      // Strip the trailing sighash byte
      const der = sigHex.slice(0, -2);
      const bytes = Buffer.from(der, 'hex');

      // SEQUENCE tag
      expect(bytes[0]).toBe(0x30);

      // Declared length should cover the rest of the DER bytes
      const seqLen = bytes[1];
      expect(seqLen).toBe(bytes.length - 2);

      // First INTEGER (R)
      expect(bytes[2]).toBe(0x02);
      const rLen = bytes[3];
      const rEnd = 4 + rLen;

      // Second INTEGER (S)
      expect(bytes[rEnd]).toBe(0x02);
      const sLen = bytes[rEnd + 1];
      const sEnd = rEnd + 2 + sLen;

      // Total consumed should equal the full DER
      expect(sEnd).toBe(bytes.length);
    });
  });

  // -------------------------------------------------------------------------
  // 6. Low-S enforcement
  // -------------------------------------------------------------------------
  describe('low-S enforcement', () => {
    it('produces an S value that is at most N/2', () => {
      // Test with a few different transactions to increase confidence
      const txids = ['aa', 'bb', 'cc', 'dd', 'ee'];
      for (const fill of txids) {
        const tx = makeTx({ sourceTXID: fill.repeat(32) });
        const { sigHex } = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000);

        // Strip sighash byte, parse DER to extract S
        const der = sigHex.slice(0, -2);
        const bytes = Buffer.from(der, 'hex');
        const rLen = bytes[3];
        const sOffset = 4 + rLen;
        const sLen = bytes[sOffset + 1];
        const sBytes = bytes.subarray(sOffset + 2, sOffset + 2 + sLen);
        const sHex = Buffer.from(sBytes).toString('hex');
        const s = new BigNumber(sHex, 16);

        expect(s.lte(HALF_N)).toBe(true);
      }
    });
  });

  // -------------------------------------------------------------------------
  // 7. Multiple inputs
  // -------------------------------------------------------------------------
  describe('multiple inputs', () => {
    it('produces different results for different input indices', () => {
      const tx = makeTx({ numInputs: 2 });
      const r0 = computeOpPushTx(tx, 0, SAMPLE_SUBSCRIPT, 10000);
      const r1 = computeOpPushTx(tx, 1, SAMPLE_SUBSCRIPT, 10000);

      expect(r0.preimageHex).not.toBe(r1.preimageHex);
      expect(r0.sigHex).not.toBe(r1.sigHex);
    });
  });
});

describe('R-178: an out-of-range codeSeparatorIndex is refused', () => {
  // String.slice() past the end returns '', so this used to sign an EMPTY
  // scriptCode — silently, from a fund-moving primitive. (Peer tiers got it
  // wrong differently: rust/python/ruby/zig signed the UNTRIMMED subscript, go
  // panicked on the slice, java threw StringIndexOutOfBounds.)
  it('throws instead of signing an empty scriptCode', () => {
    const tx = makeTx();
    const oneByte = '51'; // OP_1
    for (const idx of [1, 2, 99]) {
      expect(
        () => computeOpPushTx(tx, 0, oneByte, 10000, idx),
        `codeSeparatorIndex ${idx}`,
      ).toThrow(/codeSeparatorIndex/);
    }
  });

  it('still trims for an in-range index, and trimming changes the preimage', () => {
    const tx = makeTx();
    const twoBytes = 'ab51'; // OP_CODESEPARATOR, OP_1
    const trimmed = computeOpPushTx(tx, 0, twoBytes, 10000, 0);
    const untrimmed = computeOpPushTx(tx, 0, twoBytes, 10000);
    expect(trimmed.preimageHex).not.toBe(untrimmed.preimageHex);
  });
});
