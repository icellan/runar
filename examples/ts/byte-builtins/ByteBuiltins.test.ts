import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';
import { Hash } from '@bsv/sdk';

/**
 * ByteBuiltins at the EXAMPLES layer — the interpreter half of the oracle.
 *
 * `conformance/byte_builtins_execution_test.go` spends this contract's compiled
 * bytes on the go-sdk consensus interpreter. This file reads the same source
 * through the ANF interpreter instead, so the two halves are independent: a
 * codegen bug moves the Go test, a lowering-or-interpreter disagreement moves
 * this one, and only a bug in the SOURCE SEMANTICS moves both.
 *
 * The boundaries mirror the Go test's, because that is where the value is:
 * split at 0 and at len, int2str's sign-magnitude encoding, reverseBytes on
 * empty and odd-length input. Each group carries a negative so a builtin that
 * ignored its arguments could not pass.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'ByteBuiltins.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const PREIMAGE = 'runar byte-builtins fixture';
const DIGEST = Buffer.from(
  Hash.sha256(Array.from(Buffer.from(PREIMAGE, 'utf8'))),
).toString('hex');

/** A contract with the SHA-256 digest of PREIMAGE baked in. */
function contract() {
  return TestContract.fromSource(source, { expectedDigest: DIGEST }, FILE);
}

const call = (method: string, args: Record<string, unknown>) =>
  contract().call(method, args);

describe('ByteBuiltins — split', () => {
  // `split` binds the RIGHT half. Index 0 and index == len are the two ends of
  // the legal range and the only places an off-by-one can show.
  it.each([
    ['index 0 binds the whole string', 'aabbccdd', 0n, 'aabbccdd'],
    ['index == len binds the empty string', 'aabbccdd', 4n, ''],
    ['a mid split', 'aabbccdd', 2n, 'ccdd'],
    ['the empty string at index 0', '', 0n, ''],
  ])('accepts %s', (_name, data, idx, expectedTail) => {
    const r = call('checkSplit', { data, idx, expectedTail });
    expect(r.success, r.error).toBe(true);
  });

  it('rejects the wrong tail', () => {
    expect(call('checkSplit', { data: 'aabbccdd', idx: 2n, expectedTail: 'ccde' }).success)
      .toBe(false);
  });

  it('rejects the LEFT half — the binding is the right one', () => {
    expect(call('checkSplit', { data: 'aabbccdd', idx: 2n, expectedTail: 'aabb' }).success)
      .toBe(false);
  });
});

describe('ByteBuiltins — int2str', () => {
  // OP_NUM2BIN is fixed-width little-endian SIGN-MAGNITUDE: the sign lives in
  // the top byte, not as a two's complement. Both wrong encodings are named
  // below so a regression says which one came back.
  it.each([
    ['zero into 4 bytes', 0n, 4n, '00000000'],
    ['one into 4 bytes', 1n, 4n, '01000000'],
    ['minus one into 4 bytes', -1n, 4n, '01000080'],
    ['minus five into 4 bytes', -5n, 4n, '05000080'],
    ['255, which needs its own sign byte', 255n, 2n, 'ff00'],
    ['zero into zero width', 0n, 0n, ''],
  ])('accepts %s', (_name, value, width, expected) => {
    const r = call('checkInt2Str', { value, width, expected });
    expect(r.success, r.error).toBe(true);
  });

  it('rejects a two’s-complement encoding of -1', () => {
    expect(call('checkInt2Str', { value: -1n, width: 4n, expected: 'ffffffff' }).success)
      .toBe(false);
  });

  it('rejects a big-endian encoding of 1', () => {
    expect(call('checkInt2Str', { value: 1n, width: 4n, expected: '00000001' }).success)
      .toBe(false);
  });

  it('refuses a width too small to hold the value', () => {
    // NUM2BIN must ABORT rather than truncate — truncation is how a value
    // silently becomes a different number on chain.
    expect(call('checkInt2Str', { value: 255n, width: 1n, expected: 'ff' }).success)
      .toBe(false);
  });
});

describe('ByteBuiltins — reverseBytes', () => {
  const rev = (hex: string) =>
    Buffer.from(Buffer.from(hex, 'hex')).reverse().toString('hex');

  it.each(['', 'aa', 'aabb', 'aabbcc', '0011223344556677889900aabbccddeeff'])(
    'reverses %s',
    (data) => {
      const r = call('checkReverse', { data, expected: rev(data) });
      expect(r.success, r.error).toBe(true);
    },
  );

  it('reverses a 520-byte input — the maximum BSV stack element', () => {
    // The lowering unrolls exactly 520 iterations; this is the only input for
    // which the LAST of them does real work.
    const data = Buffer.from(Array.from({ length: 520 }, (_, i) => i % 256)).toString('hex');
    const r = call('checkReverse', { data, expected: rev(data) });
    expect(r.success, r.error).toBe(true);
  });

  it('rejects the identity — a no-op reverse must not pass', () => {
    expect(call('checkReverse', { data: 'aabbcc', expected: 'aabbcc' }).success).toBe(false);
  });

  it('rejects a 16-bit word swap', () => {
    expect(call('checkReverse', { data: '01020304', expected: '03040102' }).success).toBe(false);
  });
});

describe('ByteBuiltins — sha256', () => {
  it('accepts the preimage of the baked digest', () => {
    const r = call('checkSha256', { preimage: Buffer.from(PREIMAGE, 'utf8').toString('hex') });
    expect(r.success, r.error).toBe(true);
  });

  it('rejects the DIGEST itself', () => {
    // This is the shape of the Go-surface `runar.Sha256` defect: when the hash
    // call is lowered to an identity binding the contract degenerates to
    // `preimage == storedDigest`, and the public digest becomes the key.
    expect(call('checkSha256', { preimage: DIGEST }).success).toBe(false);
  });

  it('rejects an unrelated preimage', () => {
    expect(call('checkSha256', { preimage: '00' }).success).toBe(false);
  });
});
