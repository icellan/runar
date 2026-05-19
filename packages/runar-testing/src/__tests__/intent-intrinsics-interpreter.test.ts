/**
 * Intent-intrinsics interpreter coverage (BSVM Phase 13 Major-1 follow-up).
 *
 * The compiler desugars the four intent-covenant intrinsics
 * (`extractPrevOutputScript`, `requireOutputP2PKH`, `currentBlockHeight`,
 * plus `len`-branching on a read-only intrinsic value) into ANF chains
 * built from existing primitives (`load_param`, `hash256`, `substr`,
 * `cat`, `num2bin`, `extractLocktime`, `extractOutputHash`, `bin_op`,
 * `assert`). These tests prove that the AST interpreter accepts and
 * correctly executes the four shipping fixtures end-to-end under
 * realistic SIGHASH preimages, with witness bytes routed in through the
 * new {@link TestContract.setPrevOutScript} / {@link TestContract.setSerialisedOutputs}
 * channel.
 *
 * Per-fixture coverage:
 *   - intent-prev-output-script:    1 success + 2 failure (wrong hash, empty witness)
 *   - intent-output-p2pkh:          1 success + 2 failure (wrong PKH bytes, wrong hashOutputs)
 *   - intent-current-block-height:  1 success + 1 failure (locktime > deadline)
 *   - branched-readonly-len:        1 then-branch + 1 else-branch (no failure path: both arms succeed)
 *
 * Tier-portability note: the witness-injection API and intrinsic
 * handlers live in the TS reference tier only. Each of the six other
 * tiers (Go/Rust/Python/Zig/Ruby/Java) ships its own ANF interpreter
 * under `packages/runar-{go,rs,py,zig,rb,java}/...` (e.g.
 * `packages/runar-java/src/main/java/runar/lang/runtime/AnfInterpreter.java`,
 * `packages/runar-zig/src/sdk/anf_interpreter.zig`); each will need an
 * equivalent witness map + intent-intrinsic shim before the same
 * empirical guarantee covers it.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { TestContract } from '../test-contract.js';

// ---------------------------------------------------------------------------
// Fixture paths (worktree-rooted via __dirname)
// ---------------------------------------------------------------------------

const REPO_ROOT = join(__dirname, '..', '..', '..', '..');
const EX = (sub: string) => join(REPO_ROOT, 'examples', 'ts', sub);

const SRC_PREV = readFileSync(
  join(EX('intent-prev-output-script'), 'IntentPrevOutputScript.runar.ts'),
  'utf8',
);
const SRC_P2PKH = readFileSync(
  join(EX('intent-output-p2pkh'), 'IntentOutputP2PKH.runar.ts'),
  'utf8',
);
const SRC_BLOCK = readFileSync(
  join(EX('intent-current-block-height'), 'IntentCurrentBlockHeight.runar.ts'),
  'utf8',
);
const SRC_BRANCH = readFileSync(
  join(EX('branched-readonly-len'), 'BranchedReadonlyLen.runar.ts'),
  'utf8',
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hash256(bytes: Uint8Array): Uint8Array {
  const a = createHash('sha256').update(bytes).digest();
  return new Uint8Array(createHash('sha256').update(a).digest());
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) out[i / 2] = parseInt(s.substring(i, i + 2), 16);
  return out;
}

/** Build a canonical 34-byte P2PKH output: 8 LE amount ‖ 1976a914 ‖ pkh ‖ 88ac. */
function p2pkhOutput(amount: bigint, pkh: Uint8Array): Uint8Array {
  if (pkh.length !== 20) throw new Error('pkh must be 20 bytes');
  const out = new Uint8Array(34);
  let a = amount;
  for (let i = 0; i < 8; i++) { out[i] = Number(a & 0xffn); a >>= 8n; }
  out.set([0x19, 0x76, 0xa9, 0x14], 8);
  out.set(pkh, 12);
  out.set([0x88, 0xac], 32);
  return out;
}

// ---------------------------------------------------------------------------
// intent-prev-output-script
// ---------------------------------------------------------------------------

describe('intent-intrinsics interpreter — intent-prev-output-script', () => {
  const prevOutScript = fromHex('76a91400112233445566778899aabbccddeeff0011223388ac');
  const expectedHash = hash256(prevOutScript);

  it('success: hash256(witness) === expectedHash → call returns', () => {
    const c = TestContract.fromSource(SRC_PREV, {
      expectedHash: hex(expectedHash),
      count: 0n,
    });
    c.setPrevOutScript(0n, prevOutScript);

    const r = c.call('bind');
    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
    // count is mutable; assignment in the method must have taken effect.
    expect(c.state.count).toBe(1n);
  });

  it('failure: witness mismatches expectedHash → assertion failure', () => {
    const c = TestContract.fromSource(SRC_PREV, {
      expectedHash: hex(expectedHash),
      count: 0n,
    });
    // Different bytes → different hash256.
    c.setPrevOutScript(0n, fromHex('deadbeef'));

    const r = c.call('bind');
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/extractPrevOutputScript.*hash256/);
  });

  it('failure: no witness supplied → explicit error', () => {
    const c = TestContract.fromSource(SRC_PREV, {
      expectedHash: hex(expectedHash),
      count: 0n,
    });
    // Intentionally omit setPrevOutScript.

    const r = c.call('bind');
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/requires witness bytes/);
  });
});

// ---------------------------------------------------------------------------
// intent-output-p2pkh
// ---------------------------------------------------------------------------

describe('intent-intrinsics interpreter — intent-output-p2pkh', () => {
  const bondPKH = fromHex('00112233445566778899aabbccddeeff00112233');
  const bondAmount = 5000n;
  // Build a single 34-byte P2PKH output as the serialised-outputs witness.
  const serialised = p2pkhOutput(bondAmount, bondPKH);
  const outputHash = hash256(serialised);

  it('success: serialised P2PKH bytes match expected → call returns', () => {
    const c = TestContract.fromSource(SRC_P2PKH, {
      bondPKH: hex(bondPKH),
      bondAmount,
      count: 0n,
    });
    c.setSerialisedOutputs(serialised);
    c.setMockPreimageBytes({ outputHash });

    const r = c.call('payBond');
    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
    expect(c.state.count).toBe(1n);
  });

  it('failure: wrong pubkey-hash in serialised outputs → substring mismatch', () => {
    const wrongPKH = fromHex('ffffffffffffffffffffffffffffffffffffffff');
    const wrongSerialised = p2pkhOutput(bondAmount, wrongPKH);
    const wrongHashOutputs = hash256(wrongSerialised);

    const c = TestContract.fromSource(SRC_P2PKH, {
      bondPKH: hex(bondPKH),
      bondAmount,
      count: 0n,
    });
    c.setSerialisedOutputs(wrongSerialised);
    // hashOutputs must still match the serialised witness, otherwise the
    // outer hash check would fail first. We want the per-output substr
    // comparison to be the assertion that trips.
    c.setMockPreimageBytes({ outputHash: wrongHashOutputs });

    const r = c.call('payBond');
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/requireOutputP2PKH.*mismatch/);
  });

  it('failure: hashOutputs preimage mismatch → outer hash assertion', () => {
    const c = TestContract.fromSource(SRC_P2PKH, {
      bondPKH: hex(bondPKH),
      bondAmount,
      count: 0n,
    });
    c.setSerialisedOutputs(serialised);
    // Wrong outputHash on the preimage — desugar's first assertion fails.
    c.setMockPreimageBytes({ outputHash: new Uint8Array(32) });

    const r = c.call('payBond');
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/hash256\(serialisedOutputs\) !== preimage\.hashOutputs/);
  });
});

// ---------------------------------------------------------------------------
// intent-current-block-height
// ---------------------------------------------------------------------------

describe('intent-intrinsics interpreter — intent-current-block-height', () => {
  it('success: locktime <= deadline → assertion holds', () => {
    const c = TestContract.fromSource(SRC_BLOCK, {
      deadline: 1_000_000n,
      count: 0n,
    });
    c.setMockPreimage({ locktime: 500_000n });

    const r = c.call('spend');
    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
    expect(c.state.count).toBe(1n);
  });

  it('failure: locktime > deadline → assertion failure', () => {
    const c = TestContract.fromSource(SRC_BLOCK, {
      deadline: 100n,
      count: 0n,
    });
    c.setMockPreimage({ locktime: 999_999n });

    const r = c.call('spend');
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/assert/i);
  });
});

// ---------------------------------------------------------------------------
// branched-readonly-len — both arms succeed; verifies affine checker doesn't
// reject state mutation under a len(...)-driven branch.
// ---------------------------------------------------------------------------

describe('intent-intrinsics interpreter — branched-readonly-len', () => {
  it('then-branch: len(scratch) > 0 → count += 1, tag := scratch', () => {
    const c = TestContract.fromSource(SRC_BRANCH, {
      count: 10n,
      tag: '00',
    });
    const r = c.call('spend', { scratch: 'aabbcc' });
    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
    expect(c.state.count).toBe(11n);
    expect(c.state.tag).toBe('aabbcc');
    // Single addOutput emitted.
    expect(r.outputs).toHaveLength(1);
    expect(r.outputs[0]!.satoshis).toBe(1000n);
  });

  it('else-branch: len(scratch) == 0 → count -= 1, tag := "3030"', () => {
    const c = TestContract.fromSource(SRC_BRANCH, {
      count: 10n,
      tag: 'aa',
    });
    const r = c.call('spend', { scratch: '' });
    expect(r.success).toBe(true);
    expect(r.error).toBeUndefined();
    expect(c.state.count).toBe(9n);
    expect(c.state.tag).toBe('3030');
    expect(r.outputs).toHaveLength(1);
  });
});
