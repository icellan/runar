import { describe, it, expect } from 'vitest';
import { BigNumber, PrivateKey, Utils } from '@bsv/sdk';
import { sign as ecdsaSignRaw } from '@bsv/sdk/primitives/ECDSA';
import {
  canonicalJson,
  signEnvelope,
  verifyEnvelope,
  pubkeyToPKH,
  estimateFeeForArtifact,
  estimateCallFee,
  buildP2PKHScript,
} from '../index.js';
import type { SignedEnvelope, EnvelopeSigner } from '../envelope.js';
import type { RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Test signer — signs precomputed digests directly via raw ECDSA, matching
// the WalletSigner.signHash contract. Bypasses PrivateKey.sign()'s implicit
// SHA-256, which would otherwise produce a sig that verifies against
// sha256(digest) rather than digest.
// ---------------------------------------------------------------------------

class TestSigner implements EnvelopeSigner {
  constructor(private readonly priv: PrivateKey) {}

  async signHash(digest: number[]): Promise<string> {
    const msgBN = new BigNumber(digest);
    const sig = ecdsaSignRaw(msgBN, this.priv as unknown as BigNumber, true);
    return Utils.toHex(sig.toDER() as number[]);
  }

  async getPublicKey(): Promise<string> {
    return this.priv.toPublicKey().toDER('hex') as string;
  }
}

const ALICE = new PrivateKey(1n);
const BOB = new PrivateKey(2n);

// ---------------------------------------------------------------------------
// canonicalJson
// ---------------------------------------------------------------------------

describe('canonicalJson', () => {
  it('is insertion-order independent', () => {
    expect(canonicalJson({ a: 1, b: 2 })).toBe(canonicalJson({ b: 2, a: 1 }));
  });

  it('handles nested objects and arrays', () => {
    const a = canonicalJson({ outer: { z: 1, a: [3, 2, 1] }, list: [{ y: 1, x: 2 }] });
    const b = canonicalJson({ list: [{ x: 2, y: 1 }], outer: { a: [3, 2, 1], z: 1 } });
    expect(a).toBe(b);
  });

  it('handles primitives and null', () => {
    expect(canonicalJson(null)).toBe('null');
    expect(canonicalJson(true)).toBe('true');
    expect(canonicalJson(42)).toBe('42');
    expect(canonicalJson('hi')).toBe('"hi"');
  });
});

// ---------------------------------------------------------------------------
// pubkeyToPKH
// ---------------------------------------------------------------------------

describe('pubkeyToPKH', () => {
  it('produces the same hash160 that buildP2PKHScript inlines', () => {
    const pub = ALICE.toPublicKey().toDER('hex') as string;
    const pkh = pubkeyToPKH(pub);
    expect(pkh).toMatch(/^[0-9a-f]{40}$/);
    expect(buildP2PKHScript(pub)).toBe('76a914' + pkh + '88ac');
  });
});

// ---------------------------------------------------------------------------
// estimateFeeForArtifact
// ---------------------------------------------------------------------------

describe('estimateFeeForArtifact', () => {
  // A minimal fixture artifact — only `.script` is consulted.
  const fakeArtifact = { script: 'ab'.repeat(200) } as unknown as RunarArtifact; // 400 hex chars = 200 bytes

  it('matches estimateCallFee with documented defaults', () => {
    const expected = estimateCallFee(200, Math.ceil(400 / 4), 1, 0.1 * 1000);
    expect(estimateFeeForArtifact(fakeArtifact)).toBe(expected);
  });

  it('honors feeRate and unlockingScriptLen overrides', () => {
    const got = estimateFeeForArtifact(fakeArtifact, { feeRate: 0.5, unlockingScriptLen: 80, outputCount: 2 });
    const expected = estimateCallFee(200, 80, 2, 0.5 * 1000);
    expect(got).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// signEnvelope + verifyEnvelope — round trip + every rejection reason
// ---------------------------------------------------------------------------

describe('signEnvelope / verifyEnvelope', () => {
  const signer = new TestSigner(ALICE);

  it('round-trips a payload', async () => {
    const env = await signEnvelope({ data: { kind: 'hello', n: 7 }, signer });
    const result = verifyEnvelope({ envelope: env });
    expect(result.ok).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.data).toBeDefined();
    expect(result.data!.kind).toBe('hello');
    expect(result.data!.n).toBe(7);
    expect(result.data!.nonce).toBe(env.nonce);
    expect(result.data!.expiresAt).toBe(env.expiresAt);
  });

  it('rejects with missing-fields when sig is stripped', async () => {
    const env = await signEnvelope({ data: { ok: 1 }, signer });
    const broken = { ...env, sig: undefined as unknown as string };
    expect(verifyEnvelope({ envelope: broken as SignedEnvelope })).toEqual({
      ok: false,
      reason: 'missing-fields',
    });
  });

  it('rejects with expired when expiresAt is in the past', async () => {
    const env = await signEnvelope({ data: { ok: 1 }, signer });
    const stale = { ...env, expiresAt: Date.now() - 60_000 };
    const r = verifyEnvelope({ envelope: stale });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('expired');
  });

  it('rejects with bad-json when payload is malformed', async () => {
    const env = await signEnvelope({ data: { ok: 1 }, signer });
    const corrupt = { ...env, payload: 'not json{' };
    const r = verifyEnvelope({ envelope: corrupt });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad-json');
  });

  it('rejects with envelope-mismatch when outer nonce diverges from payload', async () => {
    const env = await signEnvelope({ data: { ok: 1 }, signer });
    const mismatched = { ...env, nonce: env.nonce + 1 };
    const r = verifyEnvelope({ envelope: mismatched });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('envelope-mismatch');
    expect(r.data).toBeDefined();
  });

  it('rejects with bad-sig when the signature has been tampered', async () => {
    const env = await signEnvelope({ data: { ok: 1 }, signer });
    // Flip the last hex char (DER tail) — keeps length valid, breaks signature.
    const flipped = env.sig.slice(0, -1) + (env.sig.slice(-1) === '0' ? '1' : '0');
    const r = verifyEnvelope({ envelope: { ...env, sig: flipped } });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad-sig');
    expect(r.data).toBeDefined();
  });

  it('rejects with pubkey-not-allowed when pubkey is outside the allowlist', async () => {
    const env = await signEnvelope({ data: { ok: 1 }, signer });
    const allowed = await new TestSigner(BOB).getPublicKey();
    const r = verifyEnvelope({ envelope: env, expectedKeys: [allowed] });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('pubkey-not-allowed');
    expect(r.data).toBeDefined();
  });

  it('accepts when pubkey is in the allowlist', async () => {
    const env = await signEnvelope({ data: { ok: 1 }, signer });
    const r = verifyEnvelope({ envelope: env, expectedKeys: [env.pubkey] });
    expect(r.ok).toBe(true);
  });
});
