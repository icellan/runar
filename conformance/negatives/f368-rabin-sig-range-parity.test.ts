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
import { RABIN_TEST_KEY, rabinSign } from '../../packages/runar-testing/src/crypto/rabin.js';
import { Tier, buildSourceTiers, compileHex, ALL_TIER_IDS } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * F-368 — the Rabin verifier never range-checked `sig` against the modulus.
 * `(sig + k*n)^2 = sig^2 (mod n)`, so a mempool observer could replace the
 * signature push of an honest spend with `sig + n` and rebroadcast a
 * functionally identical spend under a different txid. User decision R90:
 * reject the non-canonical encoding in all seven tiers — the script asserts
 * `sig < n` (sig is already >= 0 after the F-144 unsigned normalization)
 * before squaring, and aborts otherwise.
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules (`newConsensusSpend`), on the
 * hex each tier's own CLI emits — never the ANF interpreter or TestContract.
 *
 * What this proves, for every tier, fold OFF and ON:
 *   - a canonical signature (0 <= sig < n) from the off-compiler signer is
 *     ACCEPTED, and so is the second canonical root n - sig (inherent to
 *     Rabin, deliberately still accepted);
 *   - sig + n and sig + 2n with the same padding — the malleated pushes — are
 *     REFUSED (before F-368 every tier accepted them);
 *   - sig = n exactly is REFUSED. It satisfies the identity only when
 *     SHA256(msg) mod n < 65536, which never happens for a real ~2^260 key
 *     (the digest is < n, so the residue is the whole digest), so it is shown
 *     under a crafted modulus n = H - 7: there sig = 0 with padding 7 is
 *     accepted and sig = n (n^2 = 0 mod n, the same residue) is refused —
 *     the gate's upper bound is exclusive and sits exactly at n;
 *   - the script carries the gate `OP_DUP OP_3 OP_PICK OP_LESSTHAN OP_VERIFY`
 *     exactly once, directly after the sig normalization and before OP_MUL
 *     (walked opcode by opcode, so push data cannot fake a match), and every
 *     tier emits the TS reference bytes.
 * What it does NOT prove: that the crafted modulus is a secure key (it is
 * not; it only places the boundary), anything about zero-padded sig pushes
 * (`sig || 0x00` normalizes to the same number — an encoding malleability
 * F-144's normalization admits and this item does not close), or the
 * any-of-N pattern with a SHARED sig under two moduli (a sig >= the smaller
 * modulus now aborts there instead of evaluating false).
 */

const P3 = '53';
const DUP = '76';
const PICK = '79';
const LESSTHAN = '9f';
const VERIFY = '69';
const ROT = '7b';
const PUSH00 = '0100';
const CAT = '7e';
const BIN2NUM = '81';
const MUL = '95';
/** OP_ROT, sig normalization, the F-368 gate, then OP_DUP OP_MUL (the squaring). */
const GATE_WINDOW = [ROT, PUSH00, CAT, BIN2NUM, DUP, P3, PICK, LESSTHAN, VERIFY, DUP, MUL];

/** Split a script into whole opcodes (opcode byte plus any push payload). */
function walk(hex: string): string[] {
  const b = Buffer.from(hex, 'hex');
  const ops: string[] = [];
  let i = 0;
  while (i < b.length) {
    const op = b[i]!;
    const start = i++;
    if (op >= 0x01 && op <= 0x4b) i += op;
    else if (op === 0x4c) i += 1 + b[i]!;
    else if (op === 0x4d) i += 2 + b.readUInt16LE(i);
    else if (op === 0x4e) i += 4 + b.readUInt32LE(i);
    if (i > b.length) throw new Error(`truncated push at byte ${start}`);
    ops.push(b.subarray(start, i).toString('hex'));
  }
  return ops;
}

function countWindow(ops: string[], win: string[]): number {
  let n = 0;
  for (let k = 0; k + win.length <= ops.length; k++) {
    if (win.every((w, j) => ops[k + j] === w)) n++;
  }
  return n;
}

/** Non-negative value as a minimal Script number (LE magnitude + 0x00 sign byte if needed). */
function scriptNum(v: bigint): Buffer {
  const out: number[] = [];
  let x = v;
  while (x > 0n) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  if (out.length > 0 && out[out.length - 1]! & 0x80) out.push(0);
  return Buffer.from(out);
}

/** Minimal push (consensus MINIMALDATA). */
function push(data: Buffer): string {
  if (data.length === 0) return '00';
  if (data.length === 1 && data[0]! >= 0x01 && data[0]! <= 0x10) return (0x50 + data[0]!).toString(16);
  if (data.length === 1 && data[0] === 0x81) return '4f';
  if (data.length <= 75) return data.length.toString(16).padStart(2, '0') + data.toString('hex');
  if (data.length <= 255) return '4c' + data.length.toString(16).padStart(2, '0') + data.toString('hex');
  throw new Error('push: operand > 255 bytes');
}

function accepts(lockingHex: string, unlockingHex: string): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false; // a thrown validation error is a failed spend
  }
}

function digestLE(msg: Buffer): bigint {
  const h = createHash('sha256').update(msg).digest();
  let v = 0n;
  for (let i = h.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(h[i]!);
  return v;
}

/** The modulus is a literal property initializer: no constructor slot to splice. */
function source(n: bigint): string {
  return `import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';
class F368Rabin extends SmartContract {
  readonly pk: RabinPubKey = ${n}n;
  constructor() { super(); }
  public check(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.pk));
  }
}
`;
}

const unlock = (msg: Buffer, sig: bigint, padding: bigint) =>
  push(msg) + push(scriptNum(sig)) + push(scriptNum(padding));

// Real ~2^260 key, signed outside the compiler.
const N = RABIN_TEST_KEY.n;
const MSG = Buffer.from('53c3000000000000', 'hex'); // num2bin(50003, 8)
const { sig: SIG, padding: PAD } = rabinSign(MSG, RABIN_TEST_KEY);

// Crafted modulus placing sig = n on the identity: n = H - 7, so H mod n = 7.
const CRAFT_MSG = Buffer.from('f368', 'hex');
const CRAFT_PAD = 7n;
const CRAFT_N = digestLE(CRAFT_MSG) - CRAFT_PAD;

const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TS_TIER = TIERS.find((t) => t.id === 'ts');
const MODES: { label: string; tier: (t: Tier) => Tier }[] = [
  { label: 'fold OFF', tier: foldOff },
  { label: 'fold ON', tier: (t) => t },
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'f368-rabin-range-'));
});
function write(name: string, src: string): string {
  const p = join(dir, name);
  writeFileSync(p, src);
  return p;
}

describe('F-368 Rabin sig must be canonical (0 <= sig < n) — seven tiers, executed on @bsv/sdk', () => {
  it('the TS reference and at least one other tier are available (all seven in CI)', () => {
    expect(TS_TIER).toBeDefined();
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(ALL_TIER_IDS.length);
  });

  it('preconditions: the signer emits a canonical sig; the crafted modulus puts sig = n on the identity', () => {
    expect(SIG >= 0n && SIG < N).toBe(true);
    expect((SIG * SIG + PAD) % N).toBe(digestLE(MSG) % N);
    expect(((SIG + N) * (SIG + N) + PAD) % N).toBe(digestLE(MSG) % N);
    expect(((N - SIG) * (N - SIG) + PAD) % N).toBe(digestLE(MSG) % N);
    // Real key: the digest is below n, so sig = n would need padding = digest >= 65536.
    expect(digestLE(MSG) < N && digestLE(MSG) % N >= 65536n).toBe(true);
    expect(CRAFT_N > CRAFT_PAD).toBe(true);
    expect((CRAFT_N * CRAFT_N + CRAFT_PAD) % CRAFT_N).toBe(digestLE(CRAFT_MSG) % CRAFT_N);
  });

  for (const mode of MODES) {
    describe(mode.label, () => {
      let tsReal = '';
      let tsCraft = '';
      beforeAll(() => {
        tsReal = compileHex(mode.tier(TS_TIER!), write('Real.runar.ts', source(N)));
        tsCraft = compileHex(mode.tier(TS_TIER!), write('Craft.runar.ts', source(CRAFT_N)));
      }, 240_000);

      for (const tier of TIERS) {
        it(`${tier.id}: gate shape, TS bytes, canonical accepts, sig+n / sig+2n / sig=n abort`, () => {
          const real = tier.id === 'ts' ? tsReal : compileHex(mode.tier(tier), write('Real.runar.ts', source(N)));
          const craft =
            tier.id === 'ts' ? tsCraft : compileHex(mode.tier(tier), write('Craft.runar.ts', source(CRAFT_N)));

          // (a) canonical signatures accept: sig and the second root n - sig.
          expect(accepts(real, unlock(MSG, SIG, PAD)), 'canonical sig rejected').toBe(true);
          expect(accepts(real, unlock(MSG, N - SIG, PAD)), 'canonical root n - sig rejected').toBe(true);
          // (b) the malleated pushes abort.
          expect(accepts(real, unlock(MSG, SIG + N, PAD)), 'sig + n accepted').toBe(false);
          expect(accepts(real, unlock(MSG, SIG + 2n * N, PAD)), 'sig + 2n accepted').toBe(false);
          // (c) sig = n exactly (crafted modulus): sig = 0 accepts, sig = n aborts.
          expect(accepts(craft, unlock(CRAFT_MSG, 0n, CRAFT_PAD)), 'sig = 0 under crafted n rejected').toBe(true);
          expect(accepts(craft, unlock(CRAFT_MSG, CRAFT_N, CRAFT_PAD)), 'sig = n accepted').toBe(false);

          expect(countWindow(walk(real), GATE_WINDOW), 'sig < n gate window').toBe(1);
          expect(countWindow(walk(craft), GATE_WINDOW), 'sig < n gate window (crafted n)').toBe(1);
          expect(real).toBe(tsReal);
          expect(craft).toBe(tsCraft);
        }, 240_000);
      }
    });
  }
});
