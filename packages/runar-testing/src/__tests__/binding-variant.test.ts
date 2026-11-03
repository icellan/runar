/**
 * `@bindingVariant` + the C=1 Any-S OP_PUSH_TX binding (ports #170; original
 * design: brendan-elas, #167), executed through the `@bsv/sdk` Script
 * interpreter with real BIP-143 preimages.
 *
 * Both constructions derive the ECDSA signature (r = Gx, s ≡ z + 1) from
 * z = hash256(preimage) and verify it against P = (Gx⁻¹ mod n)·G, the C=1 key
 * 038ff83d…. They differ only in the low-S / mod-n fixup:
 *
 *   - lowS (default, 422 B): `00 cat bin2num 1add`, then s = lowS(s mod n).
 *     Valid at every nVersion, including 1 (the version every SDK builds).
 *   - all (opt-in, 376 B): `00 cat 1add`, s = z + 1 as-is. High-S about half
 *     the time and non-minimally encoded about half the time, so it is only
 *     spendable when the spending tx has nVersion > 1 (the @bsv/sdk relaxed
 *     regime, where LOW_S and minimal-number rules are off).
 *
 * The `bin2num` in the lowS addend is load-bearing: `00 cat` leaves a
 * redundant sign byte whenever the digest's top byte is < 0x80, and OP_1ADD
 * refuses that non-minimal number at nVersion = 1. The mutant test below
 * removes it and watches genuine spends fail.
 */

import { describe, it, expect } from 'vitest';
import {
  Curve, BigNumber, LockingScript, UnlockingScript, Spend, TransactionSignature, Hash,
} from '@bsv/sdk';
import {
  compile,
  CHECK_PREIMAGE_BINDING_HEX,
  CHECK_PREIMAGE_BINDING_ALL_HEX,
  checkPreimageBindingBytes,
} from 'runar-compiler';
import { newConsensusSpend, CONSENSUS_TX_VERSION } from '../consensus-spend.js';

const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const TWO256 = 1n << 256n;
const HALF_N = n >> 1n;

const C1_PUBKEY = '038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218';
const OLD_C2_248_PUBKEY = '02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0';
const LOWS_ADDEND = '01007e818b';
const OLD_ADDEND = '01007e8100011f80517e93';

const toHex = (u: Uint8Array | number[]) => Buffer.from(u as Uint8Array).toString('hex');

const curve = new Curve();
const bn = (x: bigint) => new BigNumber(x.toString(16), 16);
function pubkeyForAddend(c: bigint): string {
  const nB = bn(n);
  const d = bn(c).mul(bn(Gx).invm(nB)).umod(nB);
  return toHex(curve.g.mul(d).encode(true) as number[]);
}

const BASE_CTX = {
  sourceTXID: '00'.repeat(32),
  sourceOutputIndex: 0,
  sourceSatoshis: 100000,
  otherInputs: [] as never[],
  outputs: [] as never[],
  inputIndex: 0,
  inputSequence: 0xffffffff,
  lockTime: 0,
};
const SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;

function pushData(bytes: Uint8Array): string {
  const hex = toHex(bytes);
  const l = bytes.length;
  if (l < 0x4c) return l.toString(16).padStart(2, '0') + hex;
  if (l <= 0xff) return '4c' + l.toString(16).padStart(2, '0') + hex;
  return '4d' + (l & 0xff).toString(16).padStart(2, '0') + ((l >> 8) & 0xff).toString(16).padStart(2, '0') + hex;
}

/**
 * Spend `lockingHex` (preimage on the stack is all it needs) with the genuine
 * BIP-143 preimage of a context that differs per `i`, at `version`. Version 1
 * goes through `newConsensusSpend` (strict); any other version builds a plain
 * `Spend`, which @bsv/sdk treats as relaxed.
 */
function spend(lockingHex: string, version: number, i: number, subscriptHex = lockingHex): { ok: boolean; z: bigint; err?: string } {
  const ctx = { ...BASE_CTX, transactionVersion: version, lockTime: i * 101 + 1, sourceSatoshis: 100000 + i };
  const sub = LockingScript.fromHex(subscriptHex);
  const pre = Uint8Array.from(
    TransactionSignature.formatBytes({ ...ctx, subscript: sub, scope: SCOPE }) as unknown as number[],
  );
  const z = BigInt('0x' + toHex(Hash.hash256(Array.from(pre)) as number[]));
  const params = {
    ...ctx,
    lockingScript: LockingScript.fromHex(lockingHex),
    unlockingScript: UnlockingScript.fromHex(pushData(pre)),
  };
  const s = version === CONSENSUS_TX_VERSION ? newConsensusSpend(params) : new Spend(params);
  try {
    return { ok: s.validate(), z };
  } catch (e) {
    return { ok: false, z, err: e instanceof Error ? e.message : String(e) };
  }
}

/** Off-chain model of the derived s (big-endian digest read as LE + 1). */
function zScriptNum(z: bigint): bigint {
  // The blob reverses the 32-byte digest before reading it as a number, so the
  // on-chain value is the digest interpreted big-endian — i.e. z itself.
  return z;
}

describe('C=1 Any-S binding: pinned bytes', () => {
  it('default (lowS) blob is the 422-byte C=1 form', () => {
    expect(CHECK_PREIMAGE_BINDING_HEX.length / 2).toBe(422);
    expect(CHECK_PREIMAGE_BINDING_HEX).toContain(LOWS_ADDEND + '21414136d0');
    expect(CHECK_PREIMAGE_BINDING_HEX.endsWith('01417e21' + C1_PUBKEY + 'ad')).toBe(true);
    expect(CHECK_PREIMAGE_BINDING_HEX).not.toContain(OLD_C2_248_PUBKEY);
    expect(CHECK_PREIMAGE_BINDING_HEX).not.toContain(OLD_ADDEND);
  });

  it("'all' blob is the 376-byte C=1 form", () => {
    expect(CHECK_PREIMAGE_BINDING_ALL_HEX.length / 2).toBe(376);
    expect(CHECK_PREIMAGE_BINDING_ALL_HEX).toContain('7c7e01007e8b7692');
    expect(CHECK_PREIMAGE_BINDING_ALL_HEX.endsWith('01417e21' + C1_PUBKEY + 'ad')).toBe(true);
    // no mod-n / low-S block: the 33-byte n push is absent
    expect(CHECK_PREIMAGE_BINDING_ALL_HEX).not.toContain('21414136d0');
  });

  it('the old 428-byte blob is exactly the lowS blob with the addend and key swapped back', () => {
    const old = CHECK_PREIMAGE_BINDING_HEX.replace(LOWS_ADDEND, OLD_ADDEND).replace(C1_PUBKEY, OLD_C2_248_PUBKEY);
    expect(old.length / 2).toBe(428);
  });

  it('a non-default sighash flag only moves the flag push, for both variants', () => {
    const lowS43 = toHex(checkPreimageBindingBytes(0x43, 'lowS'));
    const all43 = toHex(checkPreimageBindingBytes(0x43, 'all'));
    expect(lowS43).toBe(CHECK_PREIMAGE_BINDING_HEX.replace('01417e21' + C1_PUBKEY, '01437e21' + C1_PUBKEY));
    expect(all43).toBe(CHECK_PREIMAGE_BINDING_ALL_HEX.replace('01417e21' + C1_PUBKEY, '01437e21' + C1_PUBKEY));
  });

  it('the C=1 key is (Gx⁻¹ mod n)·G; the retired C=2²⁴⁸ key is (2²⁴⁸·Gx⁻¹)·G', () => {
    expect(pubkeyForAddend(1n)).toBe(C1_PUBKEY);
    expect(pubkeyForAddend(1n << 248n)).toBe(OLD_C2_248_PUBKEY);
  });
});

describe('C=1 Any-S binding: execution through @bsv/sdk Spend', () => {
  it('lowS accepts 200/200 genuine spends at nVersion = 1 (LOW_S + minimal numbers)', () => {
    for (let i = 0; i < 200; i++) {
      const r = spend(CHECK_PREIMAGE_BINDING_HEX, 1, i);
      expect(r.ok, `lowS nVersion=1 spend ${i}: ${r.err ?? ''}`).toBe(true);
    }
  });

  it('lowS rejects a decoupled preimage at nVersion = 1', () => {
    // Push a different context's preimage: hash256 no longer equals the real sighash.
    const ctx = { ...BASE_CTX, transactionVersion: 1, lockTime: 7 };
    const wrong = Uint8Array.from(
      TransactionSignature.formatBytes({ ...ctx, lockTime: 8, subscript: LockingScript.fromHex(CHECK_PREIMAGE_BINDING_HEX), scope: SCOPE }) as unknown as number[],
    );
    const s = newConsensusSpend({
      ...ctx,
      lockingScript: LockingScript.fromHex(CHECK_PREIMAGE_BINDING_HEX),
      unlockingScript: UnlockingScript.fromHex(pushData(wrong)),
    });
    let ok = false;
    try { ok = s.validate(); } catch { ok = false; }
    expect(ok).toBe(false);
  });

  it('OP_BIN2NUM is load-bearing: without it about half of nVersion = 1 spends fail', () => {
    const mutant = CHECK_PREIMAGE_BINDING_HEX.replace(LOWS_ADDEND, '01007e8b');
    expect(mutant.length / 2).toBe(421);
    let failed = 0;
    let failedWithSmallTopByte = 0;
    const N = 120;
    for (let i = 0; i < N; i++) {
      const r = spend(mutant, 1, i);
      if (!r.ok) {
        failed++;
        // z's most-significant byte < 0x80 ⇒ `00 cat` produced a non-minimal number
        if (zScriptNum(r.z) >> 248n < 0x80n) failedWithSmallTopByte++;
      }
    }
    expect(failed).toBeGreaterThan(N / 4);
    expect(failed).toBeLessThan((3 * N) / 4);
    expect(failedWithSmallTopByte).toBe(failed);
  });

  it("'all' accepts 120/120 genuine spends at nVersion = 2 (relaxed)", () => {
    for (let i = 0; i < 120; i++) {
      const r = spend(CHECK_PREIMAGE_BINDING_ALL_HEX, 2, i);
      expect(r.ok, `all nVersion=2 spend ${i}: ${r.err ?? ''}`).toBe(true);
    }
  });

  it("'all' is rejected at nVersion = 1 for every sampled spend (why it is opt-in)", () => {
    let accepted = 0;
    for (let i = 0; i < 60; i++) if (spend(CHECK_PREIMAGE_BINDING_ALL_HEX, 1, i).ok) accepted++;
    expect(accepted).toBe(0);
  });

  it('lowS hits both low-S branches and short DER s values across the sweep', () => {
    // Deterministic coverage report over the 200-spend sweep above.
    let malleated = 0;
    let short = 0;
    for (let i = 0; i < 200; i++) {
      const { z } = spend(CHECK_PREIMAGE_BINDING_HEX, 1, i);
      let s = (z + 1n) % n;
      if (s > HALF_N) { s = n - s; malleated++; }
      if (s < 1n << 248n) short++;
    }
    expect(malleated).toBeGreaterThan(0);
    expect(malleated).toBeLessThan(200);
    expect(short).toBeGreaterThan(0);
  });
});

describe('C=1 Any-S binding: failure-rate model', () => {
  const acceptsLowS = (z: bigint) => {
    let s = (z + 1n) % n;
    if (s > HALF_N) s = n - s;
    return s >= 1n;
  };
  const acceptsAll = (z: bigint) => z + 1n < n;

  it("lowS fails only at z = n − 1 (s = 0): P = 2⁻²⁵⁶", () => {
    expect(acceptsLowS(n - 1n)).toBe(false);
    expect(acceptsLowS(n - 2n)).toBe(true);
    expect(acceptsLowS(n)).toBe(true);
    expect(acceptsLowS(TWO256 - 1n)).toBe(true);
  });

  it("'all' fails iff z ≥ n − 1: P = (2²⁵⁶ − n + 1)/2²⁵⁶ ≈ 2⁻¹²⁸", () => {
    expect(acceptsAll(n - 2n)).toBe(true);
    expect(acceptsAll(n - 1n)).toBe(false);
    const region = TWO256 - (n - 1n);
    expect(Math.round(Math.log2(Number(region) / Number(TWO256)))).toBe(-128);
  });
});

describe('@bindingVariant through compile()', () => {
  const STATELESS_ALL = `
    class AllGate extends SmartContract {
      constructor() { super(); }
      /** @bindingVariant all */
      public unlock(txPreimage: SigHashPreimage) {
        assert(checkPreimage(txPreimage));
      }
    }
  `;

  function scriptOf(src: string, fileName: string): string {
    const r = compile(src, { fileName });
    expect(r.success, (r.diagnostics ?? []).map((d) => d.message).join('\n')).toBe(true);
    return r.artifact!.script;
  }
  /** BIP-143 scriptCode: the bytes after the (single) OP_CODESEPARATOR, if any. */
  function subscriptOf(src: string, fileName: string): string {
    const r = compile(src, { fileName });
    const idx = r.artifact!.codeSeparatorIndex;
    return idx === undefined ? r.artifact!.script : r.artifact!.script.slice((idx + 1) * 2);
  }

  it('a stateless @bindingVariant all method compiles to the all blob and spends at nVersion = 2 only', () => {
    const hex = scriptOf(STATELESS_ALL, 'AllGate.runar.ts');
    const sub = subscriptOf(STATELESS_ALL, 'AllGate.runar.ts');
    expect(hex).toContain(CHECK_PREIMAGE_BINDING_ALL_HEX);
    expect(hex).not.toContain(CHECK_PREIMAGE_BINDING_HEX);
    for (let i = 0; i < 20; i++) {
      const r = spend(hex, 2, i, sub);
      expect(r.ok, `nVersion=2 spend ${i}: ${r.err ?? ''}`).toBe(true);
    }
    let acceptedV1 = 0;
    for (let i = 0; i < 20; i++) if (spend(hex, 1, i, sub).ok) acceptedV1++;
    expect(acceptedV1).toBe(0);
  });

  it('the same method without the directive compiles to the lowS blob and spends at nVersion = 1', () => {
    const src = STATELESS_ALL.replace('/** @bindingVariant all */', '');
    const hex = scriptOf(src, 'AllGate.runar.ts');
    expect(hex).toContain(CHECK_PREIMAGE_BINDING_HEX);
    for (let i = 0; i < 20; i++) {
      const r = spend(hex, 1, i, subscriptOf(src, 'AllGate.runar.ts'));
      expect(r.ok, `nVersion=1 spend ${i}: ${r.err ?? ''}`).toBe(true);
    }
  });

  it('a manual checkPreimage in an if arm inherits the method variant', () => {
    const src = `
      class ArmGate extends SmartContract {
        constructor() { super(); }
        /** @bindingVariant all */
        public unlock(txPreimage: SigHashPreimage, b: boolean) {
          if (b) {
            assert(checkPreimage(txPreimage));
          } else {
            assert(checkPreimage(txPreimage));
          }
        }
      }
    `;
    const hex = scriptOf(src, 'ArmGate.runar.ts');
    expect(hex.split(CHECK_PREIMAGE_BINDING_ALL_HEX).length - 1).toBe(2);
    expect(hex).not.toContain(CHECK_PREIMAGE_BINDING_HEX);
  });

  it('a stateful @bindingVariant all method gets the all blob in its auto-injected prologue', () => {
    const src = `
      class AllCounter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        /** @bindingVariant all */
        public bump() { this.count++; }
        public plain() { this.count--; }
      }
    `;
    const hex = scriptOf(src, 'AllCounter.runar.ts');
    expect(hex.split(CHECK_PREIMAGE_BINDING_ALL_HEX).length - 1).toBe(1);
    expect(hex.split(CHECK_PREIMAGE_BINDING_HEX).length - 1).toBe(1);
  });
});
