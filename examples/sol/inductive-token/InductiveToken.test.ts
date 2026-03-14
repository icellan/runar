import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'InductiveToken.runar.sol'), 'utf8');
const FILE_NAME = 'InductiveToken.runar.sol';

const ALICE = '02' + 'aa'.repeat(32);
const BOB = '02' + 'bb'.repeat(32);
const TOKEN_ID = 'deadbeef';
const MOCK_SIG = '30' + 'ff'.repeat(35);
const SATS = 1000n;

// Zero outpoint sentinel used for genesis detection
const ZERO_OUTPOINT = '00'.repeat(36);
const ZERO_PROOF = '00'.repeat(256);

describe('InductiveToken (Solidity)', () => {
  function makeToken(owner = ALICE, balance = 100n) {
    return TestContract.fromSource(source, {
      owner,
      balance,
      tokenId: TOKEN_ID,
      _genesisOutpoint: ZERO_OUTPOINT,
      _proof: ZERO_PROOF,
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
      expect(result.outputs[1]!.balance).toBe(70n);
    });

    it('assigns correct owners to outputs', () => {
      const token = makeToken();
      const result = token.call('transfer', {
        sig: MOCK_SIG,
        to: BOB,
        amount: 30n,
        outputSatoshis: SATS,
      });
      expect(result.outputs[0]!.owner).toBe(BOB);
      expect(result.outputs[1]!.owner).toBe(ALICE);
    });

    it('rejects transfer of zero amount', () => {
      const token = makeToken();
      const result = token.call('transfer', {
        sig: MOCK_SIG,
        to: BOB,
        amount: 0n,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });

    it('rejects transfer exceeding balance', () => {
      const token = makeToken(ALICE, 100n);
      const result = token.call('transfer', {
        sig: MOCK_SIG,
        to: BOB,
        amount: 200n,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(false);
    });
  });

  describe('send', () => {
    it('creates one output with full balance', () => {
      const token = makeToken(ALICE, 100n);
      const result = token.call('send', {
        sig: MOCK_SIG,
        to: BOB,
        outputSatoshis: SATS,
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs[0]!.owner).toBe(BOB);
      expect(result.outputs[0]!.balance).toBe(100n);
    });
  });

  describe('internal fields', () => {
    it('has inductive internal fields in initial state', () => {
      const token = makeToken();
      expect(token.state._genesisOutpoint).toBe(ZERO_OUTPOINT);
      expect(token.state._proof).toBe(ZERO_PROOF);
    });
  });
});
