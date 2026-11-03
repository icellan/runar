import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { rabinSign, rabinVerify, RABIN_TEST_KEY } from '../crypto/rabin.js';

/**
 * Regression tests for the Rabin off-chain verifier padding bound.
 *
 * The on-chain codegen (`rabin-codegen.ts` + all 6 peer tiers) enforces
 * `0 <= padding < RABIN_PADDING_LIMIT (65536)` via OP_WITHIN/OP_VERIFY. The
 * off-chain reference verifier `rabinVerify` (used by the TestContract
 * interpreter) MUST enforce the same bound, otherwise it accepts forgeries
 * the deployed script rejects — an interpreter↔script soundness divergence.
 *
 * Universal-forgery vector (the bound is the only thing that blocks it):
 *   set sig = 0 and padding = SHA256(msg). Then
 *   (0² + SHA256(msg)) mod n == SHA256(msg) mod n  → equation holds with no key.
 * SHA256(msg) is a 256-bit value (>> 65536), so the padding bound rejects it.
 */
describe('Rabin off-chain verifier padding bound (BUG-008 residual)', () => {
  const n = RABIN_TEST_KEY.n;
  const msg = new TextEncoder().encode('price=50001');

  it('rejects the universal forgery (sig=0, padding=SHA256(msg))', () => {
    // padding bytes = the raw SHA256 digest, which is interpreted unsigned-LE
    // as exactly the value the verifier compares against → forgery if unbounded.
    const forgedPadding = new Uint8Array(createHash('sha256').update(msg).digest());
    expect(rabinVerify(msg, 0n, forgedPadding, n)).toBe(false);
  });

  it('still accepts an honestly produced signature (padding < 1000)', () => {
    const { sig, padding } = rabinSign(msg, RABIN_TEST_KEY);
    expect(padding).toBeLessThan(65536n);
    // serialise padding to unsigned-LE bytes the way the verifier reads them
    const padBytes = bigintToUnsignedLE(padding);
    expect(rabinVerify(msg, sig, padBytes, n)).toBe(true);
  });

  it('rejects padding at/above the 65536 limit', () => {
    const atLimit = bigintToUnsignedLE(65536n);
    expect(rabinVerify(msg, 0n, atLimit, n)).toBe(false);
  });
});

/**
 * N-380 (F-368 follow-up): the on-chain script asserts `sig < n` before
 * squaring, so `sig + k*n` (k >= 1) aborts on chain. The off-chain verifier
 * must reject exactly the same encodings.
 *
 * Proves: rabinVerify accepts the canonical signature (and the second root
 * n - sig) and rejects sig + n, sig + 2n and sig = n for the real test key.
 * Does not prove: the verdict equals Spend's for these inputs (that is the
 * f368 negatives test, which runs the compiled script under consensus rules).
 */
describe('Rabin off-chain verifier rejects non-canonical sig >= n (N-380)', () => {
  const n = RABIN_TEST_KEY.n;
  const msg = new TextEncoder().encode('price=50001');
  const { sig, padding } = rabinSign(msg, RABIN_TEST_KEY);
  const pad = bigintToUnsignedLE(padding);

  it('accepts the canonical signature and the second root n - sig', () => {
    expect(sig < n).toBe(true);
    expect(rabinVerify(msg, sig, pad, n)).toBe(true);
    expect(rabinVerify(msg, n - sig, pad, n)).toBe(true);
  });

  it('rejects sig + n and sig + 2n', () => {
    expect(rabinVerify(msg, sig + n, pad, n)).toBe(false);
    expect(rabinVerify(msg, sig + 2n * n, pad, n)).toBe(false);
  });

  it('rejects sig = n exactly (exclusive upper bound)', () => {
    // n*n = 0 (mod n): the identity holds for a crafted digest residue, but sig = n is out of range.
    expect(rabinVerify(msg, n, pad, n)).toBe(false);
  });
});

function bigintToUnsignedLE(v: bigint): Uint8Array {
  if (v === 0n) return new Uint8Array([0]);
  const out: number[] = [];
  let x = v;
  while (x > 0n) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  return new Uint8Array(out);
}
