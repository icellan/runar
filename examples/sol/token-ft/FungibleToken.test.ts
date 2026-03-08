import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'FungibleTokenExample.runar.sol'), 'utf8');
const FILE_NAME = 'FungibleTokenExample.runar.sol';

const ALICE = '02' + 'aa'.repeat(32);
const BOB = '02' + 'bb'.repeat(32);
const TOKEN_ID = 'deadbeef';
const MOCK_SIG = '30' + 'ff'.repeat(35);
const SATS = 1000n;
const MOCK_PREVOUTS = '00'.repeat(72);

function hash256(hexData: string): Uint8Array {
  const buf = Buffer.from(hexData, 'hex');
  const sha1 = createHash('sha256').update(buf).digest();
  return new Uint8Array(createHash('sha256').update(sha1).digest());
}

const MOCK_HASH_PREVOUTS = hash256(MOCK_PREVOUTS);

describe('FungibleToken (Solidity)', () => {
  function makeToken(owner = ALICE, balance = 100n) {
    return TestContract.fromSource(source, {
      owner,
      balance,
      mergeBalance: 0n,
      tokenId: TOKEN_ID,
    }, FILE_NAME);
  }

  describe('transfer (split)', () => {
    it('creates two outputs with correct balances', () => {
      const token = makeToken();
      const result = token.call('transfer', {
        sig: MOCK_SIG,
        to: BOB,
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
      const result = token.call('transfer', { sig: MOCK_SIG, to: BOB, amount: 30n, outputSatoshis: SATS });
      expect(result.outputs[0]!.owner).toBe(BOB);
      expect(result.outputs[1]!.owner).toBe(ALICE);
    });

    it('rejects transfer of zero amount', () => {
      const result = makeToken().call('transfer', { sig: MOCK_SIG, to: BOB, amount: 0n, outputSatoshis: SATS });
      expect(result.success).toBe(false);
    });

    it('rejects transfer exceeding balance', () => {
      const result = makeToken(ALICE, 100n).call('transfer', { sig: MOCK_SIG, to: BOB, amount: 200n, outputSatoshis: SATS });
      expect(result.success).toBe(false);
    });
  });

  describe('send', () => {
    it('creates one output with full balance', () => {
      const token = makeToken(ALICE, 100n);
      const result = token.call('send', { sig: MOCK_SIG, to: BOB, outputSatoshis: SATS });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.owner).toBe(BOB);
      expect(result.outputs[0]!.balance).toBe(100n);
      expect(result.outputs[0]!.mergeBalance).toBe(0n);
    });
  });

  describe('merge', () => {
    it('creates one output with position-dependent balances', () => {
      const token = makeToken(ALICE, 30n);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const result = token.call('merge', {
        sig: MOCK_SIG,
        otherBalance: 70n,
        allPrevouts: MOCK_PREVOUTS,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.balance).toBe(30n);
      expect(result.outputs[0]!.mergeBalance).toBe(70n);
      expect(result.outputs[0]!.owner).toBe(ALICE);
    });

    it('rejects merge with negative otherBalance', () => {
      const token = makeToken(ALICE, 100n);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const result = token.call('merge', {
        sig: MOCK_SIG,
        otherBalance: -1n,
        allPrevouts: MOCK_PREVOUTS,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });

    it('rejects merge with tampered allPrevouts (hash mismatch)', () => {
      const token = makeToken(ALICE, 30n);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const tamperedPrevouts = 'ff'.repeat(72);
      const result = token.call('merge', {
        sig: MOCK_SIG,
        otherBalance: 70n,
        allPrevouts: tamperedPrevouts,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });

    it('merge with pre-existing mergeBalance uses total', () => {
      const token = TestContract.fromSource(source, {
        owner: ALICE,
        balance: 20n,
        mergeBalance: 10n,
        tokenId: TOKEN_ID,
      }, FILE_NAME);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const result = token.call('merge', {
        sig: MOCK_SIG,
        otherBalance: 50n,
        allPrevouts: MOCK_PREVOUTS,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.balance).toBe(30n);
      expect(result.outputs[0]!.mergeBalance).toBe(50n);
    });
  });

  describe('edge cases', () => {
    it('transfer of exact balance succeeds with no change output', () => {
      const token = makeToken(ALICE, 100n);
      const result = token.call('transfer', {
        sig: MOCK_SIG,
        to: BOB,
        amount: 100n,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.balance).toBe(100n);
    });

    it('transfer uses mergeBalance in total', () => {
      const token = TestContract.fromSource(source, {
        owner: ALICE,
        balance: 60n,
        mergeBalance: 40n,
        tokenId: TOKEN_ID,
      }, FILE_NAME);
      const result = token.call('transfer', {
        sig: MOCK_SIG,
        to: BOB,
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
        owner: ALICE,
        balance: 60n,
        mergeBalance: 40n,
        tokenId: TOKEN_ID,
      }, FILE_NAME);
      const result = token.call('send', {
        sig: MOCK_SIG,
        to: BOB,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs[0]!.balance).toBe(100n);
      expect(result.outputs[0]!.mergeBalance).toBe(0n);
    });
  });
});
