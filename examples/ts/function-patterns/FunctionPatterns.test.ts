import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'FunctionPatterns.runar.ts'), 'utf8');

const OWNER_PK = ALICE.pubKey;
const OWNER_SIG = signTestMessage(ALICE.privKey);

function make(balance = 10000n) {
  return TestContract.fromSource(source, { owner: OWNER_PK, balance });
}

describe('FunctionPatterns', () => {
  // --- Public method: deposit ---
  describe('deposit', () => {
    it('adds funds', () => {
      const c = make();
      c.call('deposit', { sig: OWNER_SIG, amount: 500n });
      expect(c.state.balance).toBe(10500n);
    });

    it('rejects zero', () => {
      const r = make().call('deposit', { sig: OWNER_SIG, amount: 0n });
      expect(r.success).toBe(false);
    });

    it('rejects negative', () => {
      const r = make().call('deposit', { sig: OWNER_SIG, amount: -100n });
      expect(r.success).toBe(false);
    });

    it('accumulates across calls', () => {
      const c = make();
      c.call('deposit', { sig: OWNER_SIG, amount: 100n });
      c.call('deposit', { sig: OWNER_SIG, amount: 200n });
      c.call('deposit', { sig: OWNER_SIG, amount: 300n });
      expect(c.state.balance).toBe(10600n);
    });
  });

  // --- Public method: withdraw (private method + built-in) ---
  describe('withdraw', () => {
    it('deducts without fee', () => {
      const c = make();
      c.call('withdraw', { sig: OWNER_SIG, amount: 3000n, feeBps: 0n });
      expect(c.state.balance).toBe(7000n);
    });

    it('deducts with 5% fee', () => {
      const c = make();
      c.call('withdraw', { sig: OWNER_SIG, amount: 1000n, feeBps: 500n });
      expect(c.state.balance).toBe(8950n);
    });

    it('rejects insufficient balance', () => {
      const r = make().call('withdraw', { sig: OWNER_SIG, amount: 20000n, feeBps: 0n });
      expect(r.success).toBe(false);
    });

    it('rejects when fee pushes total over balance', () => {
      const r = make().call('withdraw', { sig: OWNER_SIG, amount: 10000n, feeBps: 100n });
      expect(r.success).toBe(false);
    });
  });

  // --- Public method: scale (private helper wrapping built-in) ---
  describe('scale', () => {
    it('doubles', () => {
      const c = make();
      c.call('scale', { sig: OWNER_SIG, numerator: 2n, denominator: 1n });
      expect(c.state.balance).toBe(20000n);
    });

    it('halves', () => {
      const c = make();
      c.call('scale', { sig: OWNER_SIG, numerator: 1n, denominator: 2n });
      expect(c.state.balance).toBe(5000n);
    });

    it('three-quarters', () => {
      const c = make();
      c.call('scale', { sig: OWNER_SIG, numerator: 3n, denominator: 4n });
      expect(c.state.balance).toBe(7500n);
    });
  });

  // --- Public method: normalize (composed private helpers) ---
  describe('normalize', () => {
    it('clamps above max and rounds', () => {
      const c = make();
      c.call('normalize', { sig: OWNER_SIG, lo: 0n, hi: 8000n, step: 1000n });
      expect(c.state.balance).toBe(8000n);
    });

    it('rounds down non-aligned value', () => {
      const c = make(7777n);
      c.call('normalize', { sig: OWNER_SIG, lo: 0n, hi: 10000n, step: 1000n });
      expect(c.state.balance).toBe(7000n);
    });

    it('clamps below min', () => {
      const c = make(50n);
      c.call('normalize', { sig: OWNER_SIG, lo: 1000n, hi: 10000n, step: 500n });
      expect(c.state.balance).toBe(1000n);
    });
  });

  // --- Composition ---
  describe('multi-step workflows', () => {
    it('deposit then withdraw with fee', () => {
      const c = make();
      c.call('deposit', { sig: OWNER_SIG, amount: 5000n });
      c.call('withdraw', { sig: OWNER_SIG, amount: 5000n, feeBps: 200n });
      expect(c.state.balance).toBe(9900n);
    });

    it('scale then normalize', () => {
      const c = make();
      c.call('scale', { sig: OWNER_SIG, numerator: 3n, denominator: 4n });
      c.call('normalize', { sig: OWNER_SIG, lo: 0n, hi: 10000n, step: 1000n });
      expect(c.state.balance).toBe(7000n);
    });
  });
});
