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
import { emitMethod, emitCheckPreimageBinding, CHECK_PREIMAGE_BINDING_HEX } from 'runar-compiler';
import {
  LockingScript,
  UnlockingScript,
  Spend,
  TransactionSignature,
} from '@bsv/sdk';

// tx context shared by the preimage builder and the Spend interpreter
const CTX = {
  sourceTXID: '00'.repeat(32),
  sourceOutputIndex: 0,
  sourceSatoshis: 100000,
  transactionVersion: 2,
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
  const spend = new Spend({ ...CTX, lockingScript, unlockingScript });
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
  // Any-S construction (found by mirroring s = lowS((z + 2^248) mod n) off-chain
  // against this exact locking script — they stay valid while the blob's bytes
  // are stable, which the drift-guard test above already enforces):
  //   lockTime 1   → s ≤ n/2 (no malleation)
  //   lockTime 2   → s > n/2 (n−s malleation)
  //   lockTime 32  → s is 31 bytes (one leading zero stripped from DER)
  //   lockTime 275 → s is 30 bytes (two leading zeros stripped, ~2⁻¹⁶ case)
  it.each([[1], [2], [32], [275]])(
    'ACCEPTS the genuine preimage at DER/low-S edge context lockTime=%i',
    (lockTime) => {
      const ctx = { ...CTX, lockTime };
      const pre = Uint8Array.from(
        TransactionSignature.formatBytes({ ...ctx, subscript: LockingScript.fromHex(lockingHex), scope: SCOPE }) as unknown as number[],
      );
      const spend = new Spend({
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
      const spend = new Spend({ ...ctx, lockingScript: lock, unlockingScript: unlock });
      let ok = false;
      try { ok = spend.validate(); } catch { ok = false; }
      if (ok) accepted++;
      else throw new Error(`context ${i} (lockTime=${ctx.lockTime}) REJECTED a genuine preimage — DER/low-S edge case`);
    }
    expect(accepted).toBe(60);
  });
});
