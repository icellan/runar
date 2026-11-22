/**
 * Validates the on-chain OP_PUSH_TX preimage-binding construction (BUG-100 fix)
 * end-to-end through the BSV SDK Script interpreter.
 *
 * The construction (emitCheckPreimageBinding) assumes a preimage on the stack
 * and derives an ECDSA signature from hash256(preimage), verifying it against G
 * with OP_CHECKSIGVERIFY. It therefore accepts ONLY when the pushed preimage is
 * the real tx sighash preimage:
 *   - a preimage built for the exact tx context ⇒ ACCEPT
 *   - any other (decoupled) preimage           ⇒ REJECT
 * The second case is precisely the exploit BUG-100 allowed and this fix closes.
 */

import { describe, it, expect } from 'vitest';
import type { StackOp } from 'runar-ir-schema';
import {
  emitMethod, emitCheckPreimageBinding, checkPreimageBindingBytes,
  CHECK_PREIMAGE_BINDING_HEX, CHECK_PREIMAGE_BINDING_ALL_HEX,
} from 'runar-compiler';
import {
  LockingScript,
  UnlockingScript,
  TransactionSignature,
  Spend,
} from '@bsv/sdk';
import { newConsensusSpend, CONSENSUS_TX_VERSION } from '../consensus-spend.js';
import { PROVEN_BINDING_FLAGS, PROVEN_BINDING_VARIANTS } from '../oracle/proven-binding-blobs.js';

// tx context shared by the preimage builder and the Spend interpreter
const CTX = {
  sourceTXID: '00'.repeat(32),
  sourceOutputIndex: 0,
  sourceSatoshis: 100000,
  // F-055: version 1, as every SDK-built tx. At version 2 Spend is relaxed and
  // never checked that the derived signature is low-S.
  transactionVersion: CONSENSUS_TX_VERSION,
  otherInputs: [] as never[],
  outputs: [] as never[],
  inputIndex: 0,
  inputSequence: 0xffffffff,
  lockTime: 0,
};
const SCOPE =
  TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;

function pushDataHex(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString('hex');
  const n = bytes.length;
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xff) return '4c' + n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xffff) {
    const lo = (n & 0xff).toString(16).padStart(2, '0');
    const hi = ((n >> 8) & 0xff).toString(16).padStart(2, '0');
    return '4d' + lo + hi + hex;
  }
  throw new Error('preimage too large');
}

function buildConstructionHex(): string {
  const ops: StackOp[] = [];
  emitCheckPreimageBinding((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 'checkPreimage', ops, maxStackDepth: 200 });
  return scriptHex;
}

function runWith(preimage: Uint8Array, lockingHex: string): { ok: boolean; err?: string } {
  const lockingScript = LockingScript.fromHex(lockingHex);
  const unlockingScript = UnlockingScript.fromHex(pushDataHex(preimage));
  const spend = newConsensusSpend({ ...CTX, lockingScript, unlockingScript });
  try {
    return { ok: spend.validate() };
  } catch (e) {
    return { ok: false, err: e instanceof Error ? e.message : String(e) };
  }
}

describe('BUG-100 fix: on-chain OP_PUSH_TX preimage binding', () => {
  const lockingHex = buildConstructionHex();
  const lockingScript = LockingScript.fromHex(lockingHex);

  // The genuine BIP-143 preimage for CTX with subscript = the construction.
  const realPreimage = Uint8Array.from(
    TransactionSignature.formatBytes({ ...CTX, subscript: lockingScript, scope: SCOPE }) as unknown as number[],
  );

  it('emits a non-trivial locking script', () => {
    expect(lockingHex.length).toBeGreaterThan(200);
  });

  it('the pinned cross-tier constant matches the generator (drift guard)', () => {
    expect(lockingHex).toBe(CHECK_PREIMAGE_BINDING_HEX);
  });

  it('ACCEPTS the genuine tx-sighash preimage', () => {
    const r = runWith(realPreimage, lockingHex);
    expect(r.err, r.err).toBeUndefined();
    expect(r.ok).toBe(true);
  });

  it('REJECTS a decoupled preimage (the BUG-100 exploit)', () => {
    // Flip the hashOutputs region (bytes ~104..136) — a forged continuation
    // preimage that is NOT the real tx sighash. Must fail the derived CHECKSIG.
    const forged = new Uint8Array(realPreimage);
    for (let i = 104; i < 136 && i < forged.length; i++) forged[i] = ((forged[i] ?? 0) ^ 0xff) & 0xff;
    const r = runWith(forged, lockingHex);
    expect(r.ok).toBe(false);
  });

  it('REJECTS a zeroed preimage', () => {
    const zero = new Uint8Array(realPreimage.length);
    const r = runWith(zero, lockingHex);
    expect(r.ok).toBe(false);
  });

  // Ground contexts that deterministically hit the rare encoding edges of the
  // Any-S construction (found by mirroring s = lowS((z + 1) mod n) off-chain
  // against this exact locking script — they stay valid while the blob's bytes
  // are stable, which the drift-guard test above already enforces):
  //   lockTime 1     → s ≤ n/2 (no malleation)
  //   lockTime 4     → s > n/2 (n−s malleation)
  //   lockTime 146   → s is 31 bytes (one leading zero stripped from DER)
  //   lockTime 51410 → s is 30 bytes with its top bit set (~2⁻¹⁷ case): the
  //                    0x00 sign byte becomes the DER pad. The former
  //                    `DUP OP_0NOTEQUAL` fan-out REJECTED this class at
  //                    nVersion = 1 (see binding-variant.test.ts).
  // (Re-derived for the C=1 blob, ports #170. The C=2²⁴⁸ blob's version-1
  // values were 2, 1, 234 and 8963; new script bytes move every sighash.)
  it.each([[1], [4], [146], [51410]])(
    'ACCEPTS the genuine preimage at DER/low-S edge context lockTime=%i',
    (lockTime) => {
      const ctx = { ...CTX, lockTime };
      const pre = Uint8Array.from(
        TransactionSignature.formatBytes({ ...ctx, subscript: LockingScript.fromHex(lockingHex), scope: SCOPE }) as unknown as number[],
      );
      const spend = newConsensusSpend({
        ...ctx,
        lockingScript: LockingScript.fromHex(lockingHex),
        unlockingScript: UnlockingScript.fromHex(pushDataHex(pre)),
      });
      expect(spend.validate()).toBe(true);
    },
  );

  // Sweep many tx contexts: each yields a different sighash z ⇒ different s,
  // exercising the variable-length DER encoding of s and both low-S branches.
  it('ACCEPTS across 60 distinct sighashes (variable-length DER + low-S)', () => {
    let accepted = 0;
    for (let i = 0; i < 60; i++) {
      const ctx = { ...CTX, lockTime: i * 7919 + 1, sourceSatoshis: 100000 + i * 131 };
      const sub = LockingScript.fromHex(lockingHex);
      const pre = Uint8Array.from(
        TransactionSignature.formatBytes({ ...ctx, subscript: sub, scope: SCOPE }) as unknown as number[],
      );
      const lock = LockingScript.fromHex(lockingHex);
      const unlock = UnlockingScript.fromHex(pushDataHex(pre));
      const spend = newConsensusSpend({ ...ctx, lockingScript: lock, unlockingScript: unlock });
      let ok = false;
      try { ok = spend.validate(); } catch { ok = false; }
      if (ok) accepted++;
      else throw new Error(`context ${i} (lockTime=${ctx.lockTime}) REJECTED a genuine preimage — DER/low-S edge case`);
    }
    expect(accepted).toBe(60);
  });
});

// ---------------------------------------------------------------------------
// D25: the same exploit proof over EVERY blob a tier may emit — both variants
// and every sighash flag the compiler bakes in (0x41 default, 0x43
// SINGLE|FORKID for mutate-only stateful contracts, 0xC3 for their
// ANYONECANPAY form). The flag is part of the derived signature, so OP_CHECKSIG
// recomputes the sighash under THAT scope: a 0x43 blob must accept the genuine
// SINGLE preimage and reject the ALL preimage of the very same transaction.
// `conformance/preimage-binding/preimage-binding.test.ts` accepts a tier's
// contract only if it carries one of these (PROVEN_BINDING_FLAGS x VARIANTS).
// ---------------------------------------------------------------------------
const P2PKH_A = '76a914' + '11'.repeat(20) + '88ac';
const P2PKH_B = '76a914' + '22'.repeat(20) + '88ac';
const TWO_OUTPUTS = [
  { satoshis: 1000, lockingScript: LockingScript.fromHex(P2PKH_A) },
  { satoshis: 2000, lockingScript: LockingScript.fromHex(P2PKH_B) },
] as never[];

for (const variant of PROVEN_BINDING_VARIANTS) {
  for (const flag of PROVEN_BINDING_FLAGS) {
    const label = `${variant} blob, flag 0x${flag.toString(16)}`;
    // `all` is only spendable at nVersion > 1 (binding-variant.test.ts), where
    // @bsv/sdk's Spend is relaxed; lowS goes through the strict v1 rule set.
    const version = variant === 'lowS' ? CONSENSUS_TX_VERSION : 2;
    describe(`BUG-100 binding proof — ${label}`, () => {
      const lockingHex = Buffer.from(checkPreimageBindingBytes(flag, variant)).toString('hex');
      const ctxFor = (i: number) => ({
        ...CTX, transactionVersion: version, outputs: TWO_OUTPUTS,
        lockTime: i * 7919 + 1, sourceSatoshis: 100000 + i * 131,
      });
      const preimageOf = (ctx: ReturnType<typeof ctxFor>, scope: number) => Uint8Array.from(
        TransactionSignature.formatBytes({ ...ctx, subscript: LockingScript.fromHex(lockingHex), scope }) as unknown as number[],
      );
      const run = (ctx: ReturnType<typeof ctxFor>, pre: Uint8Array): { ok: boolean; err?: string } => {
        const params = {
          ...ctx,
          lockingScript: LockingScript.fromHex(lockingHex),
          unlockingScript: UnlockingScript.fromHex(pushDataHex(pre)),
        };
        const spend = version === CONSENSUS_TX_VERSION ? newConsensusSpend(params) : new Spend(params);
        try { return { ok: spend.validate() }; } catch (e) { return { ok: false, err: e instanceof Error ? e.message : String(e) }; }
      };

      it('the blob carries the flag in its derived-signature tail', () => {
        expect(lockingHex).toContain('01' + flag.toString(16).padStart(2, '0') + '7e21');
        if (flag === 0x41) {
          expect(lockingHex).toBe(variant === 'lowS' ? CHECK_PREIMAGE_BINDING_HEX : CHECK_PREIMAGE_BINDING_ALL_HEX);
        }
      });

      it('ACCEPTS the genuine preimage across 60 contexts', () => {
        for (let i = 0; i < 60; i++) {
          const ctx = ctxFor(i);
          const r = run(ctx, preimageOf(ctx, flag));
          expect(r.ok, `${label} context ${i}: ${r.err ?? ''}`).toBe(true);
        }
      });

      it('REJECTS a decoupled preimage (another context\'s genuine preimage)', () => {
        const r = run(ctxFor(3), preimageOf(ctxFor(4), flag));
        expect(r.ok).toBe(false);
      });

      it('REJECTS a forged hashOutputs field', () => {
        const ctx = ctxFor(5);
        const forged = preimageOf(ctx, flag);
        // BIP-143 tail: hashOutputs(32) || nLockTime(4) || sighashType(4).
        const at = forged.length - 40;
        for (let i = at; i < at + 32; i++) forged[i] = (forged[i]! ^ 0xff) & 0xff;
        expect(run(ctx, forged).ok).toBe(false);
      });

      it('REJECTS a zeroed preimage', () => {
        const ctx = ctxFor(6);
        expect(run(ctx, new Uint8Array(preimageOf(ctx, flag).length)).ok).toBe(false);
      });

      it('REJECTS the same transaction\'s genuine preimage under any OTHER scope', () => {
        const ctx = ctxFor(7);
        for (const other of [0x41, 0x43, 0xc1, 0xc3, 0x42]) {
          if (other === flag) continue;
          expect(run(ctx, preimageOf(ctx, other)).ok, `scope 0x${other.toString(16)}`).toBe(false);
        }
      });
    });
  }
}
