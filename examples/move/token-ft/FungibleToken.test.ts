import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'FungibleTokenExample.runar.move'), 'utf8');
const FILE_NAME = 'FungibleTokenExample.runar.move';

const TOKEN_ID = 'deadbeef';
const ALICE_SIG = signTestMessage(ALICE.privKey);
const SATS = 1000n;
const MOCK_PREVOUTS = '00'.repeat(72);

function hash256(hexData: string): Uint8Array {
  const buf = Buffer.from(hexData, 'hex');
  const sha1 = createHash('sha256').update(buf).digest();
  return new Uint8Array(createHash('sha256').update(sha1).digest());
}

const MOCK_HASH_PREVOUTS = hash256(MOCK_PREVOUTS);

describe('FungibleToken (Move)', () => {
  function makeToken(owner = ALICE.pubKey, balance = 100n) {
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
      const result = token.call('transfer', { sig: ALICE_SIG, to: BOB.pubKey, amount: 30n, outputSatoshis: SATS });
      expect(result.outputs[0]!.owner).toBe(BOB.pubKey);
      expect(result.outputs[1]!.owner).toBe(ALICE.pubKey);
    });

    it('rejects transfer of zero amount', () => {
      const result = makeToken().call('transfer', { sig: ALICE_SIG, to: BOB.pubKey, amount: 0n, outputSatoshis: SATS });
      expect(result.success).toBe(false);
    });

    it('rejects transfer exceeding balance', () => {
      const result = makeToken(ALICE.pubKey, 100n).call('transfer', { sig: ALICE_SIG, to: BOB.pubKey, amount: 200n, outputSatoshis: SATS });
      expect(result.success).toBe(false);
    });
  });

  describe('send', () => {
    it('creates one output with full balance', () => {
      const token = makeToken(ALICE.pubKey, 100n);
      const result = token.call('send', { sig: ALICE_SIG, to: BOB.pubKey, outputSatoshis: SATS });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.owner).toBe(BOB.pubKey);
      expect(result.outputs[0]!.balance).toBe(100n);
      expect(result.outputs[0]!.mergeBalance).toBe(0n);
    });
  });

  describe('merge', () => {
    it('creates one output with position-dependent balances', () => {
      const token = makeToken(ALICE.pubKey, 30n);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const result = token.call('merge', {
        sig: ALICE_SIG,
        otherBalance: 70n,
        allPrevouts: MOCK_PREVOUTS,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.balance).toBe(30n);
      expect(result.outputs[0]!.mergeBalance).toBe(70n);
      expect(result.outputs[0]!.owner).toBe(ALICE.pubKey);
    });

    it('rejects merge with negative otherBalance', () => {
      const token = makeToken(ALICE.pubKey, 100n);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const result = token.call('merge', {
        sig: ALICE_SIG,
        otherBalance: -1n,
        allPrevouts: MOCK_PREVOUTS,
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
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });

    it('merge with pre-existing mergeBalance uses total', () => {
      const token = TestContract.fromSource(source, {
        owner: ALICE.pubKey,
        balance: 20n,
        mergeBalance: 10n,
        tokenId: TOKEN_ID,
      }, FILE_NAME);
      token.setMockPreimageBytes({ hashPrevouts: MOCK_HASH_PREVOUTS });
      const result = token.call('merge', {
        sig: ALICE_SIG,
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
      }, FILE_NAME);
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
      }, FILE_NAME);
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
