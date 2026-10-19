import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BitwiseOps.runar.sol'), 'utf8');
const FILE_NAME = 'BitwiseOps.runar.sol';

// The caller supplies the expected shift / AND / OR / XOR results and the
// contract checks them (F-167: it used to assert only tautologies, so no input
// could fail). The wrong-value cases below are what prove the asserts now
// constrain something; they run on the interpreter only — the on-chain
// accept/reject for the same values is pinned by
// conformance/witnesses/real-crypto/bitwise-ops.json on @bsv/sdk's Spend.
// a = 12, b = 10 are 1-byte operands whose results stay below 0x80, so the
// byte-array opcodes agree with integer arithmetic for every value used here.
describe('BitwiseOps (Solidity)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { a: 42n, b: 17n }, FILE_NAME);
    expect(c.state.a).toBe(42n);
    expect(c.state.b).toBe(17n);
  });

  it('testShift accepts the correct results (12 << 2 = 48, 12 >> 1 = 6)', () => {
    const c = TestContract.fromSource(source, { a: 12n, b: 10n }, FILE_NAME);
    const r = c.call('testShift', { expectedLeft: 48n, expectedRight: 6n });
    expect(r.success).toBe(true);
  });

  it('testShift REJECTS a wrong left-shift result', () => {
    const c = TestContract.fromSource(source, { a: 12n, b: 10n }, FILE_NAME);
    const r = c.call('testShift', { expectedLeft: 49n, expectedRight: 6n });
    expect(r.success).toBe(false);
  });

  it('testShift REJECTS a wrong right-shift result', () => {
    const c = TestContract.fromSource(source, { a: 12n, b: 10n }, FILE_NAME);
    const r = c.call('testShift', { expectedLeft: 48n, expectedRight: 7n });
    expect(r.success).toBe(false);
  });

  it('testBitwise accepts the correct results (8, 14, 6)', () => {
    const c = TestContract.fromSource(source, { a: 12n, b: 10n }, FILE_NAME);
    const r = c.call('testBitwise', { expectedAnd: 8n, expectedOr: 14n, expectedXor: 6n });
    expect(r.success).toBe(true);
  });

  it('testBitwise REJECTS swapped AND / OR results', () => {
    const c = TestContract.fromSource(source, { a: 12n, b: 10n }, FILE_NAME);
    const r = c.call('testBitwise', { expectedAnd: 14n, expectedOr: 8n, expectedXor: 6n });
    expect(r.success).toBe(false);
  });

  it('testBitwise is UNSPENDABLE for these values (non-minimal AND result)', () => {
  // a=42, b=17 -> 42 & 17 = 0, and OP_AND PRESERVES the operands' 1-byte
  // length, so the result is the NON-MINIMAL [0x00]. The next line consumes it
  // with `===`, a numeric op, and every numeric op on chain decodes with
  // fRequireMinimal=true and ABORTS. So this spend is impossible, whatever
  // expected values the caller supplies.
  //
  // Verified against consensus (`Spend.validate()`), not just the interpreter:
  //   a=42,b=17 -> interp=false spend=false      a=0,b=0 -> both accept
  //   a=1,b=1   -> interp=false spend=false      a=3,b=1 -> both accept
  //
  // Until 2026-08-17 the interpreter re-minimised the result and this asserted
  // `.toBe(true)` — a green test for a spend no node would accept.
    const c = TestContract.fromSource(source, { a: 42n, b: 17n }, FILE_NAME);
    const r = c.call('testBitwise', { expectedAnd: 0n, expectedOr: 59n, expectedXor: 59n });
    expect(r.success).toBe(false);
  });

  it('testBitwise runs on zero', () => {
    const c = TestContract.fromSource(source, { a: 0n, b: 0n }, FILE_NAME);
    const r = c.call('testBitwise', { expectedAnd: 0n, expectedOr: 0n, expectedXor: 0n });
    expect(r.success).toBe(true);
  });
});
