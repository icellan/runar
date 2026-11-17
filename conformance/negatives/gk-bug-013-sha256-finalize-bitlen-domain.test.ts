import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * GK-BUG-013 — sha256Finalize must refuse a msgBitLen outside [0, 2^64).
 *
 * The emitted prologue turned msgBitLen into the 8-byte length suffix with
 * `<9> OP_NUM2BIN <8> OP_SPLIT OP_DROP`. OP_NUM2BIN to 9 bytes puts the
 * script-number sign in the 9th byte, and OP_DROP threw it away unchecked, so
 * every value whose low 8 bytes match an honest length hashed the same padded
 * block:
 *
 *   -24      -> 18 00 00 00 00 00 00 00 | 80   (sign byte dropped: length 24)
 *   2^64+24  -> 18 00 00 00 00 00 00 00 | 01   (high byte dropped: length 24)
 *
 * A contract that also uses the length (an upper bound, a byte count) accepted
 * a value the digest does not describe. The fix keeps the 9th byte and requires
 * it to be 0x00 (`<00> OP_EQUALVERIFY`) in all seven emitters, which is exactly
 * "msgBitLen in [0, 2^64)": every value in that range has a 9-byte NUM2BIN form
 * ending in 0x00, a negative one ends in 0x80, and anything from 2^64 up either
 * ends in a non-zero byte or does not fit in 9 bytes (OP_NUM2BIN aborts).
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules via `newConsensusSpend`, the
 * honest digest from node's SHA-256, and a FIPS 180-4 compression written here
 * (anchored to node's SHA-256('abc') below) for the upper-half control — never
 * the compiler, the ANF interpreter or TestContract.
 *
 * What this proves: for every available tier, fold OFF and ON, the compiled
 * sha256Finalize accepts the honest (IV, 'abc', 24) with SHA-256('abc'), accepts
 * a length in the upper half of the domain (2^63 + 24) with the digest of that
 * padded block, and REFUSES -24 and 2^64 + 24 presented with SHA-256('abc') --
 * the two aliases the old OP_DROP accepted -- with the failure pinned to the
 * new sign-byte OP_EQUALVERIFY (message, locking-script context, program
 * counter, and the 8-byte magnitude it had just split off).
 * What it does NOT prove: anything about remaining-length handling (F-114 /
 * F-142 pin that) or the off-chain implementations (each SDK's own
 * gk-bug-013 test pins those).
 */

const SRC = `import { SmartContract, assert, sha256Finalize } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class FinalizeBitLen extends SmartContract {
  constructor() { super(); }

  public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint, expected: ByteString) {
    assert(sha256Finalize(state, remaining, msgBitLen) === expected);
  }
}
`;

// ---------------------------------------------------------------------------
// Independent reference (FIPS 180-4 §6.2.2), anchored to node's SHA-256.
// ---------------------------------------------------------------------------

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;

function refCompress(state: Buffer, block: Buffer): Buffer {
  const H = Array.from({ length: 8 }, (_, i) => state.readUInt32BE(i * 4));
  const W = Array.from({ length: 16 }, (_, i) => block.readUInt32BE(i * 4));
  for (let t = 16; t < 64; t++) {
    const s0 = rotr(W[t - 15]!, 7) ^ rotr(W[t - 15]!, 18) ^ (W[t - 15]! >>> 3);
    const s1 = rotr(W[t - 2]!, 17) ^ rotr(W[t - 2]!, 19) ^ (W[t - 2]! >>> 10);
    W.push((W[t - 16]! + s0 + W[t - 7]! + s1) >>> 0);
  }
  let [a, b, c, d, e, f, g, h] = H as [number, number, number, number, number, number, number, number];
  for (let t = 0; t < 64; t++) {
    const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t]! + W[t]!) >>> 0;
    const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
    h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
  }
  const out = Buffer.alloc(32);
  [a, b, c, d, e, f, g, h].forEach((x, i) => out.writeUInt32BE((H[i]! + x) >>> 0, i * 4));
  return out;
}

/** One-block finalize of a short tail with an arbitrary 64-bit length field. */
function refFinalize1(state: Buffer, tail: Buffer, lengthField: bigint): Buffer {
  const block = Buffer.alloc(64);
  tail.copy(block);
  block[tail.length] = 0x80;
  block.writeBigUInt64BE(lengthField, 56);
  return refCompress(state, block);
}

const IV = Buffer.from('6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19', 'hex');
const ABC = Buffer.from('abc');
const SHA_ABC = createHash('sha256').update(ABC).digest();
const UPPER = (1n << 63n) + 24n;

// ---------------------------------------------------------------------------
// Unlocking-script encoding (consensus MINIMALDATA, version-1 strict Spend)
// ---------------------------------------------------------------------------

function scriptNum(n: bigint): Buffer {
  if (n === 0n) return Buffer.alloc(0);
  const neg = n < 0n;
  let m = neg ? -n : n;
  const out: number[] = [];
  while (m > 0n) {
    out.push(Number(m & 0xffn));
    m >>= 8n;
  }
  if (out[out.length - 1]! & 0x80) out.push(neg ? 0x80 : 0x00);
  else if (neg) out[out.length - 1]! |= 0x80;
  return Buffer.from(out);
}

function push(data: Buffer): string {
  if (data.length === 0) return '00';
  if (data.length === 1 && data[0]! >= 1 && data[0]! <= 16) return (0x50 + data[0]!).toString(16);
  if (data.length === 1 && data[0] === 0x81) return '4f';
  if (data.length > 75) throw new Error('push: test data stays under 76 bytes');
  return data.length.toString(16).padStart(2, '0') + data.toString('hex');
}

function unlocking(bitLen: bigint, expected: Buffer): string {
  return push(IV) + push(ABC) + push(scriptNum(bitLen)) + push(expected);
}

interface Outcome {
  accepted: boolean;
  message?: string;
  context?: string;
  pc?: number;
  stack?: number[][];
}

function spend(lockingHex: string, unlockingHex: string): Outcome {
  try {
    const ok = newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
    return { accepted: ok };
  } catch (e) {
    const err = e as { message?: string; context?: string; programCounter?: number; stackState?: number[][] };
    return { accepted: false, message: err.message, context: err.context, pc: err.programCounter, stack: err.stackState };
  }
}

/**
 * Chunk index of the sign-byte check: the OP_EQUALVERIFY in
 * `<9> OP_NUM2BIN <8> OP_SPLIT <00> OP_EQUALVERIFY`. -1 when the script has no
 * such window (the pre-fix `OP_DROP` form).
 */
function signCheckIndex(lockingHex: string): number {
  const chunks = LockingScript.fromHex(lockingHex).chunks;
  const isPushByte = (i: number, b: number) =>
    chunks[i]?.op === 0x01 && chunks[i]?.data?.length === 1 && chunks[i]?.data?.[0] === b;
  let found = -1;
  for (let i = 4; i < chunks.length; i++) {
    if (
      chunks[i - 4]!.op === 0x80 && // OP_NUM2BIN
      chunks[i - 3]!.op === 0x58 && // OP_8
      chunks[i - 2]!.op === 0x7f && // OP_SPLIT
      isPushByte(i - 1, 0x00) && // <00>
      chunks[i]!.op === 0x88 // OP_EQUALVERIFY
    ) {
      if (found !== -1) throw new Error('signCheckIndex: more than one sign-byte check window');
      found = i;
    }
  }
  return found;
}

function expectSignByteRefusal(o: Outcome, lockingHex: string): void {
  expect(o.accepted, 'Spend ACCEPTED an aliased msgBitLen with the honest digest').toBe(false);
  expect(o.message ?? '').toMatch(/OP_EQUALVERIFY requires the top two stack items to be equal/);
  expect(o.context).toBe('LockingScript');
  const at = signCheckIndex(lockingHex);
  expect(at, 'no `<00> OP_EQUALVERIFY` sign-byte check after the 9-byte OP_NUM2BIN').toBeGreaterThan(0);
  expect(o.pc, 'the refusal came from some other OP_EQUALVERIFY').toBe(at);
  // Below the pushed `false` sits the 8-byte LE magnitude the split produced:
  // the refusal happened right after splitting off the 9th byte.
  const below = o.stack?.[o.stack.length - 2];
  expect(Buffer.from(below ?? []).toString('hex')).toBe('1800000000000000');
}

const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const MODES: { label: string; tier: (t: Tier) => Tier }[] = [
  { label: 'fold OFF', tier: foldOff },
  { label: 'fold ON', tier: (t) => t },
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'gk-bug-013-'));
});

describe('GK-BUG-013 references are anchored', () => {
  it("refFinalize1(IV, 'abc', 24) equals node SHA-256('abc')", () => {
    expect(refFinalize1(IV, ABC, 24n).toString('hex')).toBe(SHA_ABC.toString('hex'));
  });
  it('on Spend, `<n> <9> OP_NUM2BIN` gives the aliases the same low 8 bytes as 24 (the bug, measured)', () => {
    // Locking script: OP_9 OP_NUM2BIN <9-byte expectation> OP_EQUAL.
    const nine = (n: bigint, want: string) =>
      spend(`5980${push(Buffer.from(want, 'hex'))}87`, push(scriptNum(n))).accepted;
    expect(nine(24n, '180000000000000000')).toBe(true);
    expect(nine(-24n, '180000000000000080')).toBe(true);
    expect(nine((1n << 64n) + 24n, '180000000000000001')).toBe(true);
    expect(nine(UPPER, '180000000000008000')).toBe(true);
    // Control: the harness can say no.
    expect(nine(-24n, '180000000000000000')).toBe(false);
  });
});

describe('GK-BUG-013 sha256Finalize refuses msgBitLen outside [0, 2^64) on Spend', () => {
  it('the TS reference and at least one other tier are available (all seven in CI)', () => {
    expect(TIERS.some((t) => t.id === 'ts')).toBe(true);
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const mode of MODES) {
    describe(mode.label, () => {
      for (const tier of TIERS) {
        it(`${tier.id}: honest and upper-half lengths accept; -24 and 2^64+24 are refused at the sign-byte check`, () => {
          const p = join(dir, `F-${tier.id}-${mode.label.replace(' ', '')}.runar.ts`);
          writeFileSync(p, SRC);
          const hex = compileHex(mode.tier(tier), p);

          const honest = spend(hex, unlocking(24n, SHA_ABC));
          expect(honest.accepted, `honest (IV, 'abc', 24) refused: ${honest.message}`).toBe(true);

          const upperDigest = refFinalize1(IV, ABC, UPPER);
          const upper = spend(hex, unlocking(UPPER, upperDigest));
          expect(upper.accepted, `2^63 + 24 (inside the domain) refused: ${upper.message}`).toBe(true);

          expectSignByteRefusal(spend(hex, unlocking(-24n, SHA_ABC)), hex);
          expectSignByteRefusal(spend(hex, unlocking((1n << 64n) + 24n, SHA_ABC)), hex);
        }, 240_000);
      }
    });
  }
});
