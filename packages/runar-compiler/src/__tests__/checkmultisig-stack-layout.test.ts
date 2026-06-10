import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from '../index.js';
// @ts-expect-error vitest resolves this via alias
import { ScriptVM } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// BUG-009 regression: checkMultiSig stack layout must place sigs, sig-count,
// pubkeys, pubkey-count, and the dummy at the correct depths so that
// OP_CHECKMULTISIG actually runs the signature verification loop.
//
// Before the fix the locking script was structurally OP_TRUE: it accepted any
// (or no) signatures because nSigs was read off as 0 from a stray empty-bytes
// slot. See _review/BUG-003-finding.md (sibling worktree) for the original
// trace.
// ---------------------------------------------------------------------------

/** 33-byte compressed pubkey placeholders (constructor args). Real curve
 *  points are not required because we drive OP_CHECKMULTISIG via a
 *  controlled checkSigCallback. */
const PK1 = new Uint8Array(33); PK1[0] = 0x02; PK1.fill(0xaa, 1);
const PK2 = new Uint8Array(33); PK2[0] = 0x02; PK2.fill(0xbb, 1);
const PK3 = new Uint8Array(33); PK3[0] = 0x02; PK3.fill(0xcc, 1);

/** DER-shaped signature placeholders (varied lengths to expose mis-pops). */
const SIG1 = new Uint8Array(72); SIG1[0] = 0x30; SIG1.fill(0x11, 1);
const SIG2 = new Uint8Array(72); SIG2[0] = 0x30; SIG2.fill(0x22, 1);
const SIG3 = new Uint8Array(72); SIG3[0] = 0x30; SIG3.fill(0x33, 1);

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Encode bytes as a Bitcoin Script push. */
function encodePush(b: Uint8Array): string {
  const n = b.length;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + bytesToHex(b);
  if (n < 0x100) return '4c' + n.toString(16).padStart(2, '0') + bytesToHex(b);
  throw new Error('push too large for test');
}

/** Compile MultiSig2of3, splice constructor args, and return the substituted
 *  locking script hex (no state, since the contract is stateless). */
function buildMultiSigLockingScript(pks: [Uint8Array, Uint8Array, Uint8Array]): string {
  const source = readFileSync(
    join(__dirname, '../../../../examples/ts/multisig-2of3/MultiSig2of3.runar.ts'),
    'utf8',
  );
  const result = compile(source);
  if (!result.success || !result.scriptHex || !result.artifact) {
    throw new Error('compile failed');
  }
  let script = result.scriptHex.toLowerCase();

  const slots = result.artifact.constructorSlots ?? [];
  // Descending byte-offset order so earlier splices don't shift later ones.
  const sorted = [...slots].sort((a, b) => b.byteOffset - a.byteOffset);
  for (const slot of sorted) {
    const arg = pks[slot.paramIndex]!;
    const enc = encodePush(arg);
    const hexOffset = slot.byteOffset * 2;
    // Replace the 1-byte OP_0 placeholder (2 hex chars) with the encoded value.
    script = script.slice(0, hexOffset) + enc + script.slice(hexOffset + 2);
  }
  return script;
}

/** Build an unlocking script that pushes the supplied sigs in order. */
function buildUnlockingScript(sigs: Uint8Array[]): string {
  return sigs.map(encodePush).join('');
}

/** Step the script through ScriptVM, return the stack snapshots at every
 *  step keyed by the executed opcode name. */
function stepAll(unlocking: string, locking: string, cb?: (sig: Uint8Array, pk: Uint8Array) => boolean) {
  const vm = new ScriptVM({ checkSigCallback: cb });
  vm.loadHex(unlocking, locking);
  const steps: { opcode: string; mainStack: Uint8Array[] }[] = [];
  while (true) {
    const s = vm.step();
    if (!s) break;
    steps.push({ opcode: s.opcode, mainStack: s.mainStack });
    if (s.error) break;
  }
  return steps;
}

describe('BUG-009: checkMultiSig stack layout', () => {
  it('compiles MultiSig2of3 to a real OP_CHECKMULTISIG layout, not OP_TRUE', () => {
    const script = buildMultiSigLockingScript([PK1, PK2, PK3]);
    // The pre-fix layout was 13 bytes of nonsense ending in OP_CHECKMULTISIG.
    // The fixed layout pushes 3 pubkeys (3 * 34 bytes = 102 bytes) plus a few
    // opcodes for sig/key counts, dummy, and ROLLs.
    expect(script.length / 2).toBeGreaterThan(100);
    expect(script.endsWith('ae')).toBe(true); // OP_CHECKMULTISIG
  });

  it('places the right items at the right depths when stepped through ScriptVM', () => {
    const locking = buildMultiSigLockingScript([PK1, PK2, PK3]);
    const unlocking = buildUnlockingScript([SIG1, SIG2]);
    const steps = stepAll(unlocking, locking, () => true);

    // Find the OP_CHECKMULTISIG step and look at the stack JUST BEFORE it.
    const cmsIdx = steps.findIndex(s => s.opcode === 'OP_CHECKMULTISIG');
    expect(cmsIdx).toBeGreaterThan(0);
    const beforeStack = steps[cmsIdx - 1]!.mainStack;
    // Layout bottom -> top:
    //   dummy(empty) | sig1 | sig2 | 2 | pk1 | pk2 | pk3 | 3
    expect(beforeStack.length).toBeGreaterThanOrEqual(8);
    const top8 = beforeStack.slice(-8);
    expect(bytesToHex(top8[0]!)).toBe(''); // dummy = empty bytes (OP_0)
    expect(bytesToHex(top8[1]!)).toBe(bytesToHex(SIG1));
    expect(bytesToHex(top8[2]!)).toBe(bytesToHex(SIG2));
    expect(bytesToHex(top8[3]!)).toBe('02'); // OP_2 -> minimal-num 0x02
    expect(bytesToHex(top8[4]!)).toBe(bytesToHex(PK1));
    expect(bytesToHex(top8[5]!)).toBe(bytesToHex(PK2));
    expect(bytesToHex(top8[6]!)).toBe(bytesToHex(PK3));
    expect(bytesToHex(top8[7]!)).toBe('03'); // OP_3
  });

  it('REJECTS all-false signature verification (always-false callback)', () => {
    const locking = buildMultiSigLockingScript([PK1, PK2, PK3]);
    const unlocking = buildUnlockingScript([SIG1, SIG2]);
    const vm = new ScriptVM({ checkSigCallback: () => false });
    const r = vm.execute(hexToBytes(unlocking), hexToBytes(locking));
    expect(r.success).toBe(false);
  });

  it('REJECTS all-empty signatures', () => {
    const locking = buildMultiSigLockingScript([PK1, PK2, PK3]);
    const unlocking = encodePush(new Uint8Array(0)) + encodePush(new Uint8Array(0));
    // Even with an always-true callback, an empty-sig would still be checked
    // against a real pubkey by the callback. Here we use a strict callback
    // that returns false for empty sigs (mimicking real ECDSA).
    const vm = new ScriptVM({
      checkSigCallback: (sig: Uint8Array) => sig.length > 0,
    });
    const r = vm.execute(hexToBytes(unlocking), hexToBytes(locking));
    expect(r.success).toBe(false);
  });

  it('REJECTS a single signature pushed twice (below threshold via dup)', () => {
    // Push only one distinct sig but provide two stack items. With a callback
    // that only validates (sig1->pk1, sig2->pk2, sig2->pk3) — i.e. only the
    // ordered pairing succeeds — a dup'd sig1 cannot satisfy both slots.
    const locking = buildMultiSigLockingScript([PK1, PK2, PK3]);
    const unlocking = buildUnlockingScript([SIG1, SIG1]);
    const callback = (sig: Uint8Array, pk: Uint8Array) =>
      (bytesToHex(sig) === bytesToHex(SIG1) && bytesToHex(pk) === bytesToHex(PK1)) ||
      (bytesToHex(sig) === bytesToHex(SIG2) && (bytesToHex(pk) === bytesToHex(PK2) || bytesToHex(pk) === bytesToHex(PK3))) ||
      (bytesToHex(sig) === bytesToHex(SIG3) && bytesToHex(pk) === bytesToHex(PK3));
    const vm = new ScriptVM({ checkSigCallback: callback });
    const r = vm.execute(hexToBytes(unlocking), hexToBytes(locking));
    expect(r.success).toBe(false);
  });

  it('REJECTS sigs supplied in wrong order (sig2 before sig1)', () => {
    // OP_CHECKMULTISIG requires sigs to match pubkeys in the SAME relative
    // order as their corresponding pubkeys appear in the committed array.
    // Supplying [sig2, sig1] (i.e. sig2 was meant for pk2, sig1 for pk1, but
    // pushed in reverse) will fail because the verify loop pops sigs top-down
    // and walks pubkeys forward.
    const locking = buildMultiSigLockingScript([PK1, PK2, PK3]);
    const unlocking = buildUnlockingScript([SIG2, SIG1]); // wrong order
    const callback = (sig: Uint8Array, pk: Uint8Array) =>
      (bytesToHex(sig) === bytesToHex(SIG1) && bytesToHex(pk) === bytesToHex(PK1)) ||
      (bytesToHex(sig) === bytesToHex(SIG2) && bytesToHex(pk) === bytesToHex(PK2));
    const vm = new ScriptVM({ checkSigCallback: callback });
    const r = vm.execute(hexToBytes(unlocking), hexToBytes(locking));
    expect(r.success).toBe(false);
  });

  it('ACCEPTS a valid 2-of-3 unlock (sig1->pk1, sig2->pk2)', () => {
    const locking = buildMultiSigLockingScript([PK1, PK2, PK3]);
    const unlocking = buildUnlockingScript([SIG1, SIG2]);
    const callback = (sig: Uint8Array, pk: Uint8Array) =>
      (bytesToHex(sig) === bytesToHex(SIG1) && bytesToHex(pk) === bytesToHex(PK1)) ||
      (bytesToHex(sig) === bytesToHex(SIG2) && bytesToHex(pk) === bytesToHex(PK2));
    const vm = new ScriptVM({ checkSigCallback: callback });
    const r = vm.execute(hexToBytes(unlocking), hexToBytes(locking));
    expect(r.success).toBe(true);
  });

  it('ACCEPTS a valid 2-of-3 unlock (sig1->pk1, sig2->pk3)', () => {
    const locking = buildMultiSigLockingScript([PK1, PK2, PK3]);
    const unlocking = buildUnlockingScript([SIG1, SIG2]);
    const callback = (sig: Uint8Array, pk: Uint8Array) =>
      (bytesToHex(sig) === bytesToHex(SIG1) && bytesToHex(pk) === bytesToHex(PK1)) ||
      (bytesToHex(sig) === bytesToHex(SIG2) && bytesToHex(pk) === bytesToHex(PK3));
    const vm = new ScriptVM({ checkSigCallback: callback });
    const r = vm.execute(hexToBytes(unlocking), hexToBytes(locking));
    expect(r.success).toBe(true);
  });

  it('ACCEPTS a valid 2-of-3 unlock (sig1->pk2, sig2->pk3)', () => {
    const locking = buildMultiSigLockingScript([PK1, PK2, PK3]);
    const unlocking = buildUnlockingScript([SIG1, SIG2]);
    const callback = (sig: Uint8Array, pk: Uint8Array) =>
      (bytesToHex(sig) === bytesToHex(SIG1) && bytesToHex(pk) === bytesToHex(PK2)) ||
      (bytesToHex(sig) === bytesToHex(SIG2) && bytesToHex(pk) === bytesToHex(PK3));
    const vm = new ScriptVM({ checkSigCallback: callback });
    const r = vm.execute(hexToBytes(unlocking), hexToBytes(locking));
    expect(r.success).toBe(true);
  });
});
