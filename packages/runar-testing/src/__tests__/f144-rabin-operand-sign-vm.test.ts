/**
 * F-144 — Rabin operands pushed as raw unsigned little-endian bytes.
 *
 * Every off-chain Rabin verifier reads `padding` (and, in the Go / Rust /
 * Python / Ruby / Zig native layers, `sig` and `n` too) as an UNSIGNED
 * little-endian integer. On chain, OP_WITHIN / OP_MUL / OP_MOD read a stack
 * item as a Script number: little-endian SIGN-MAGNITUDE, the high bit of the
 * last byte is the sign. A raw push whose last byte is >= 0x80 therefore
 * meant something else on chain:
 *
 *   - padding = 200 pushed as [0xC8] read as -72, so the OP_WITHIN gate
 *     aborted an honest spend;
 *   - a modulus whose last LE byte has the high bit set read as negative;
 *   - likewise a signature.
 *
 * Fix (user decision R46): verifyRabinSig appends 0x00 and applies
 * OP_BIN2NUM to each of n, padding and sig before using it. For a raw
 * unsigned push that yields the unsigned value; for a non-negative Script
 * number (what every SDK emits for a bigint) it is the identity.
 *
 * Oracle: @bsv/sdk's production `Spend` (via `runStatelessSigned`, consensus
 * flags). The ANF interpreter verdict is compared as a second opinion only.
 *
 * What this proves: on the TS-tier compiled script, an honest signature whose
 * padding, modulus or signature is pushed as raw unsigned LE bytes with the
 * last byte's high bit set is accepted, sig+1 is still refused, and the same
 * signatures pushed as Script numbers are still accepted.
 * What it does NOT prove: the six peer tiers (pinned by the oracle-price
 * golden + its real-crypto witness), or that a NEGATIVE Script number keeps
 * its meaning: normalization reads its bytes as unsigned, by design. The
 * Mersenne-product key here is not a secure key; it only fixes the byte shape.
 *
 * F-286 (user decision R78): the modulus can no longer be a spending-method
 * argument — the frontend refuses that as a universal forgery. So the modulus
 * is now a contract property. A Script-number modulus is baked through
 * `constructorArgs` (the same bytes the old argument push carried). The two
 * RAW-modulus cases are re-homed to a raw construction: the SDK splices the
 * raw 0xFF-terminated LE modulus into the constructor slot as plain push data
 * (`RunarContract` with a hex-string arg), the unlocking script pushes
 * msg / sig / padding, and real `Spend` runs that. The interpreter leg holds
 * the same raw bytes as the property's value (`TestContract` with a
 * `Uint8Array` property), so both engines still see the identical operand.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { compile } from 'runar-compiler';
import { RunarContract } from 'runar-sdk';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';
import { newConsensusSpend, CONSENSUS_SPEND_CONTEXT } from '../consensus-spend.js';
import { TestContract } from '../test-contract.js';
import { bytesToHex } from '../vm/utils.js';
import { rabinSign, rabinVerify, RABIN_TEST_KEY, type RabinKeyPair } from '../crypto/rabin.js';

const SOURCE = `
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinOperands extends SmartContract {
  readonly pk: RabinPubKey;

  constructor(pk: RabinPubKey) {
    super(pk);
    this.pk = pk;
  }

  public check(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.pk));
  }
}
`;

/** Unsigned little-endian bytes, minimal (no sign byte). */
function rawLE(v: bigint): Uint8Array {
  const out: number[] = [];
  let x = v;
  while (x > 0n) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  return new Uint8Array(out);
}

/** Non-negative value as a minimal Script number (unsigned LE + 0x00 sign byte if needed). */
function scriptNum(v: bigint): Uint8Array {
  const out = Array.from(rawLE(v));
  if (out.length > 0 && out[out.length - 1]! & 0x80) out.push(0);
  return new Uint8Array(out);
}

function lastByte(b: Uint8Array): number {
  return b[b.length - 1]!;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return r;
}

/** Honest Rabin signature with a CHOSEN padding (the signer's choice, not a forgery). */
function signWithPadding(msg: Uint8Array, kp: RabinKeyPair, padding: bigint): bigint {
  const h = createHash('sha256').update(msg).digest();
  let hBN = 0n;
  for (let i = h.length - 1; i >= 0; i--) hBN = (hBN << 8n) | BigInt(h[i]!);
  const t = (((hBN - padding) % kp.n) + kp.n) % kp.n;
  const sp = modPow(t, (kp.p + 1n) / 4n, kp.p);
  const sq = modPow(t, (kp.q + 1n) / 4n, kp.q);
  const s =
    (sp * kp.q * modPow(kp.q, kp.p - 2n, kp.p) + sq * kp.p * modPow(kp.p, kp.q - 2n, kp.q)) % kp.n;
  if ((s * s + padding) % kp.n !== hBN % kp.n) throw new Error('padding is not a QR residue for this msg');
  return s;
}

/** num2bin(price, 8): the message shape OraclePriceFeed signs. */
function priceMsg(price: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = price;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Modulus baked as a Script number through constructorArgs. */
function run(msg: Uint8Array, sig: Uint8Array, padding: Uint8Array, n: bigint) {
  return runStatelessSigned({
    source: SOURCE,
    fileName: 'RabinOperands.runar.ts',
    method: 'check',
    args: [msg, sig, padding],
    constructorArgs: { pk: n },
  });
}

/** Minimal push (consensus MINIMALDATA), as `runStatelessSigned` encodes args. */
function push(data: Uint8Array): Uint8Array {
  if (data.length === 0) return new Uint8Array([0x00]);
  if (data.length === 1 && data[0]! >= 0x01 && data[0]! <= 0x10) return new Uint8Array([0x50 + data[0]!]);
  if (data.length === 1 && data[0] === 0x81) return new Uint8Array([0x4f]);
  if (data.length > 75) throw new Error('push: test operands are <= 75 bytes');
  return new Uint8Array([data.length, ...data]);
}

/**
 * Raw construction: the modulus is spliced into the constructor slot as RAW
 * push data (no sign byte), exactly the bytes the old spending-argument push
 * carried. Real `Spend` runs the fold-ON script; the interpreter holds the
 * same raw bytes as the property's value.
 */
function runRawModulus(msg: Uint8Array, sig: Uint8Array, padding: Uint8Array, nRaw: Uint8Array) {
  const compiled = compile(SOURCE, { fileName: 'RabinOperands.runar.ts', disableConstantFolding: false });
  if (!compiled.success || !compiled.artifact) {
    throw new Error(compiled.diagnostics.map((d) => d.message).join('; '));
  }
  const lockingHex = new RunarContract(compiled.artifact, [bytesToHex(nRaw)]).getLockingScript();
  // The spliced slot must be the raw modulus push itself, or this is not the
  // construction the test claims.
  if (!lockingHex.includes(bytesToHex(push(nRaw)))) throw new Error('raw modulus push not found in locking script');
  const unlockingHex = bytesToHex(new Uint8Array([...push(msg), ...push(sig), ...push(padding)]));

  let reachedEngine = false;
  let vmAccepted = false;
  let vmError: string | undefined;
  try {
    const spend = newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      otherInputs: [],
      outputs: [],
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
    });
    reachedEngine = true;
    vmAccepted = spend.validate();
  } catch (e) {
    vmError = e instanceof Error ? e.message : String(e);
  }

  let interpreterAccepted: boolean;
  try {
    const tc = TestContract.fromSource(SOURCE, { pk: nRaw }, 'RabinOperands.runar.ts');
    interpreterAccepted = tc.call('check', { msg, sig, padding }).success;
  } catch {
    interpreterAccepted = false;
  }
  return { reachedEngine, vmAccepted, vmError, interpreterAccepted };
}

// A 216-bit modulus whose most-significant (last LE) byte is 0xFF: the
// product of the Mersenne primes 2^127-1 and 2^89-1 (both ≡ 3 mod 4).
const P127 = (1n << 127n) - 1n;
const P89 = (1n << 89n) - 1n;
const HIGH_BIT_KEY: RabinKeyPair = { p: P127, q: P89, n: P127 * P89 };

describe('F-144: Rabin operands pushed as raw unsigned LE bytes keep their meaning on chain', () => {
  describe('padding = 200 pushed as [0xC8] (real ~2^260 key)', () => {
    const msg = priceMsg(50004n);
    const sig = signWithPadding(msg, RABIN_TEST_KEY, 200n);
    const pad = new Uint8Array([0xc8]);

    it('precondition: off-chain accepts and the padding byte has its high bit set', () => {
      expect(lastByte(pad) & 0x80).toBe(0x80);
      expect(rabinVerify(msg, sig, pad, RABIN_TEST_KEY.n)).toBe(true);
    });

    it('honest signature: real Spend accepts (it read the padding as -72 and aborted OP_WITHIN)', () => {
      const r = run(msg, scriptNum(sig), pad, RABIN_TEST_KEY.n);
      expect(r.reachedEngine).toBe(true);
      expect(r.vmAccepted, `Spend refused an honest padding=200 signature: ${r.vmError}`).toBe(true);
      expect(r.interpreterAccepted).toBe(true);
    });

    it('sig+1 is still refused by both engines', () => {
      expect(rabinVerify(msg, sig + 1n, pad, RABIN_TEST_KEY.n)).toBe(false);
      const r = run(msg, scriptNum(sig + 1n), pad, RABIN_TEST_KEY.n);
      expect(r.reachedEngine).toBe(true);
      expect(r.vmAccepted).toBe(false);
      expect(r.interpreterAccepted).toBe(false);
    });
  });

  describe('modulus with last LE byte 0xFF pushed raw (216-bit key)', () => {
    const msg = priceMsg(50003n);
    const { sig, padding } = rabinSign(msg, HIGH_BIT_KEY);
    const nRaw = rawLE(HIGH_BIT_KEY.n);
    const sigRaw = rawLE(sig);

    it('precondition: off-chain accepts; n and sig raw bytes both end in a high-bit byte', () => {
      expect(lastByte(nRaw)).toBe(0xff);
      expect(lastByte(sigRaw) & 0x80).toBe(0x80);
      expect(padding < 128n).toBe(true);
      expect(rabinVerify(msg, sig, rawLE(padding), HIGH_BIT_KEY.n)).toBe(true);
    });

    it('raw modulus: real Spend accepts the honest signature', () => {
      const r = runRawModulus(msg, scriptNum(sig), rawLE(padding), nRaw);
      expect(r.reachedEngine).toBe(true);
      expect(r.vmAccepted, `Spend refused an honest signature under a raw high-bit modulus: ${r.vmError}`).toBe(true);
      expect(r.interpreterAccepted).toBe(true);
    });

    it('raw signature: real Spend accepts the honest signature', () => {
      const r = run(msg, sigRaw, rawLE(padding), HIGH_BIT_KEY.n);
      expect(r.reachedEngine).toBe(true);
      expect(r.vmAccepted, `Spend refused an honest raw high-bit signature: ${r.vmError}`).toBe(true);
      expect(r.interpreterAccepted).toBe(true);
    });

    it('raw modulus and raw sig+1: both engines refuse', () => {
      expect(rabinVerify(msg, sig + 1n, rawLE(padding), HIGH_BIT_KEY.n)).toBe(false);
      const r = runRawModulus(msg, rawLE(sig + 1n), rawLE(padding), nRaw);
      expect(r.reachedEngine).toBe(true);
      expect(r.vmAccepted).toBe(false);
      expect(r.interpreterAccepted).toBe(false);
    });

    it('the same signature pushed as Script numbers is still accepted (normalization is the identity there)', () => {
      const r = run(msg, scriptNum(sig), scriptNum(padding), HIGH_BIT_KEY.n);
      expect(r.vmAccepted, `vmErr=${r.vmError}`).toBe(true);
      expect(r.interpreterAccepted).toBe(true);
    });
  });
});
