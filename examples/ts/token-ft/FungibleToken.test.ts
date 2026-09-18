// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/token-ft.json
// (real deploy->call->@bsv/sdk Spend on THIS source, with a pinned expectedState).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'FungibleTokenExample.runar.ts'), 'utf8');

const TOKEN_ID = 'deadbeef';
const ALICE_SIG = signTestMessage(ALICE.privKey);
const SATS = 1000n;

// Mock allPrevouts: 2 outpoints × 36 bytes = 72 bytes of zeros
const MOCK_PREVOUTS = '00'.repeat(72);

// Compute hash256(allPrevouts) for the mock preimage
function hash256(hexData: string): Uint8Array {
  const buf = Buffer.from(hexData, 'hex');
  const sha1 = createHash('sha256').update(buf).digest();
  const sha2 = createHash('sha256').update(sha1).digest();
  return new Uint8Array(sha2);
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function u16le(n: number): string {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(n);
  return buf.toString('hex');
}

function u64le(n: bigint): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n);
  return buf.toString('hex');
}

function compactSizeHex(n: number): string {
  if (n < 253) return n.toString(16).padStart(2, '0');
  if (n <= 0xffff) return 'fd' + u16le(n);
  throw new Error(`CompactSize ${n} too large for this test`);
}

function buildParentTx(outCount: number, output0ScriptHex: string): string {
  const version = '01000000';
  const input = '00'.repeat(36) + '00' + 'ffffffff';
  const dummyOut = '00'.repeat(8) + '00';
  const out0 = u64le(1n) + compactSizeHex(output0ScriptHex.length / 2) + output0ScriptHex;
  if (outCount < 1) throw new Error('need output 0');
  return version + '01' + input + compactSizeHex(outCount) + out0 + dummyOut.repeat(outCount - 1) + '00000000';
}

const MOCK_HASH_PREVOUTS = hash256(MOCK_PREVOUTS);

describe('FungibleToken', () => {
  function makeToken(owner = ALICE.pubKey, balance = 100n) {
    return TestContract.fromSource(source, {
      owner,
      balance,
      mergeBalance: 0n,
      tokenId: TOKEN_ID,
    });
  }

  describe('transfer (split)', () => {
    it('creates two outputs with correct balances', () => {
      const token = makeToken();
      const result = token.call('transfer', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        amount: 30n,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(2);
      expect(result.outputs[0]!.balance).toBe(30n);
      expect(result.outputs[0]!.mergeBalance).toBe(0n);
      expect(result.outputs[1]!.balance).toBe(70n);
      expect(result.outputs[1]!.mergeBalance).toBe(0n);
    });

    it('assigns correct owners to outputs', () => {
      const token = makeToken();
      const result = token.call('transfer', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        amount: 30n,
        outputSatoshis: SATS,
      });
      expect(result.outputs[0]!.owner).toBe(BOB.pubKey);
      expect(result.outputs[1]!.owner).toBe(ALICE.pubKey);
    });

    it('sets satoshis on each output', () => {
      const token = makeToken();
      const result = token.call('transfer', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        amount: 30n,
        outputSatoshis: SATS,
      });
      expect(result.outputs[0]!.satoshis).toBe(SATS);
      expect(result.outputs[1]!.satoshis).toBe(SATS);
    });

    it('rejects transfer of zero amount', () => {
      const token = makeToken();
      const result = token.call('transfer', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        amount: 0n,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });

    it('rejects transfer exceeding balance', () => {
      const token = makeToken(ALICE.pubKey, 100n);
      const result = token.call('transfer', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        amount: 200n,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });
  });

  describe('send', () => {
    it('creates one output with full balance', () => {
      const token = makeToken(ALICE.pubKey, 100n);
      const result = token.call('send', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.owner).toBe(BOB.pubKey);
      expect(result.outputs[0]!.balance).toBe(100n);
      expect(result.outputs[0]!.mergeBalance).toBe(0n);
    });
  });

  describe('merge', () => {
    it('rejects the mock-zero prevouts path (W8: that was the solo-merge hole)', () => {
      // INTERPRETER-ONLY. The 72-zero allPrevouts trick is the exploit the
      // companion-parent walk now refuses. Honest two-input Spend is pinned
      // by w8-token-ft-solo-merge-known-broken.test.ts.
      const token = makeToken(ALICE.pubKey, 30n);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const result = token.call('merge', {
        sig: ALICE_SIG,
        otherBalance: 70n,
        allPrevouts: MOCK_PREVOUTS,
        otherParentTx: '00'.repeat(64),
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });

    it('rejects merge with negative otherBalance', () => {
      const token = makeToken(ALICE.pubKey, 100n);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const result = token.call('merge', {
        sig: ALICE_SIG,
        otherBalance: -1n,
        allPrevouts: MOCK_PREVOUTS,
        otherParentTx: '00'.repeat(64),
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });

    it('rejects merge with tampered allPrevouts (hash mismatch)', () => {
      const token = makeToken(ALICE.pubKey, 30n);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const tamperedPrevouts = 'ff'.repeat(72);
      const result = token.call('merge', {
        sig: ALICE_SIG,
        otherBalance: 70n,
        allPrevouts: tamperedPrevouts,
        otherParentTx: '00'.repeat(64),
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });

    it('parses a companion parent whose outCount CompactSize is 0xfd + LE16', () => {
      // 253 outputs force a 3-byte CompactSize. A 1-byte read then treats
      // off+9 as the script marker and lands inside the 8-byte amount.
      const otherPrimary = 70n;
      const otherMerge = 0n;
      const postCodeSepLen = 300;
      const filler = '51'.repeat(postCodeSepLen - 49);
      const tail = ALICE.pubKey + u64le(otherPrimary) + u64le(otherMerge);
      const postCodeSep = filler + tail;
      expect(postCodeSep.length / 2).toBe(postCodeSepLen);
      const companionScript = '61ab' + postCodeSep;
      const scriptCodeHex = compactSizeHex(postCodeSepLen) + postCodeSep;

      const parentHex = buildParentTx(253, companionScript);
      const companionTxid = Buffer.from(hash256(parentHex)).toString('hex');
      const myOutpoint = '11'.repeat(36);
      const companionOutpoint = companionTxid + '00000000';
      const allPrevouts = myOutpoint + companionOutpoint;

      const token = makeToken(ALICE.pubKey, 30n);
      token.setMockPreimageBytes({
        hashPrevouts: hash256(allPrevouts),
        outpoint: hexToBytes(myOutpoint),
        scriptCode: hexToBytes(scriptCodeHex),
      });
      const result = token.call('merge', {
        sig: ALICE_SIG,
        otherBalance: otherPrimary + otherMerge,
        allPrevouts,
        otherParentTx: parentHex,
        outputSatoshis: SATS,
      });
      expect(result.success, result.error).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.balance).toBe(30n);
      expect(result.outputs[0]!.mergeBalance).toBe(70n);
    });
  });

  describe('edge cases', () => {
    it('transfer of exact balance succeeds with no change output', () => {
      const token = makeToken(ALICE.pubKey, 100n);
      const result = token.call('transfer', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        amount: 100n,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.balance).toBe(100n);
    });

    it('transfer uses mergeBalance in total', () => {
      const token = TestContract.fromSource(source, {
        owner: ALICE.pubKey,
        balance: 60n,
        mergeBalance: 40n,
        tokenId: TOKEN_ID,
      });
      const result = token.call('transfer', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        amount: 80n,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs[0]!.balance).toBe(80n);
      expect(result.outputs[1]!.balance).toBe(20n);
      expect(result.outputs[0]!.mergeBalance).toBe(0n);
      expect(result.outputs[1]!.mergeBalance).toBe(0n);
    });

    it('send uses mergeBalance in total', () => {
      const token = TestContract.fromSource(source, {
        owner: ALICE.pubKey,
        balance: 60n,
        mergeBalance: 40n,
        tokenId: TOKEN_ID,
      });
      const result = token.call('send', {
        sig: ALICE_SIG,
        to: BOB.pubKey,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs[0]!.balance).toBe(100n);
      expect(result.outputs[0]!.mergeBalance).toBe(0n);
    });
  });
});
