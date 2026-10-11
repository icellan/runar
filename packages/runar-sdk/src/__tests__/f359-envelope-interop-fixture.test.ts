import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BigNumber, PrivateKey, Utils } from '@bsv/sdk';
import { sign as ecdsaSignRaw } from '@bsv/sdk/primitives/ECDSA';
import { signEnvelope, verifyEnvelope } from '../index.js';
import type { EnvelopeSigner, SignedEnvelope, VerifyEnvelopeReason } from '../envelope.js';

// Same signer shape as envelope.test.ts's TestSigner (not exported from the
// module under test): signs a precomputed digest directly via raw ECDSA,
// deterministic low-S — the same `sign` call validate-fixtures.ts uses to
// pin signing_vectors[].expected_sig.
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

// ---------------------------------------------------------------------------
// F-359 — the TS SDK's envelope is the one tier with no injectable clock, so
// it is the one tier that cannot replay the shared frozen-time interop fixture
// (conformance/sdk-envelope/fixtures.json) the way Go/Rust/Python/Zig/Ruby/
// Java each do in their own `*envelope_interop*` test. `valid_envelope`'s
// expiresAt is 1700000030000 (2023) and `verify_now_ms` is 1700000000500: under
// the real wall clock (what verifyEnvelope used exclusively before this fix)
// the expiry check at step 2 short-circuits to 'expired' before the committed
// envelope and its rejection vectors are ever exercised against anything but
// a live clock's shape.
//
// This file is the TS tier's counterpart to
// packages/runar-go/sdk_envelope_interop_test.go /
// packages/runar-py/tests/test_envelope_interop.py: it loads the SAME
// committed fixture and replays `valid_envelope` (the accept case) and every
// entry of `rejection_vectors` (the known-bad cases) against the fixture's
// own frozen `verify_now_ms`, using the new `nowMs` option on
// `verifyEnvelope`. It also exercises `clock_skew_vectors`, since those
// vectors are the direct, fixture-pinned specification of the explicit-zero
// vs. not-supplied semantics `nowMs`/`clockSkewMs` must honor.
//
// Does not prove: anything about the six peer tiers (each has its own interop
// file, listed alongside this one in conformance/wire-primitives.json); the
// depth / malleability / der-* vectors, which envelope.test.ts still replays
// via `vi.spyOn(Date, 'now')` rather than `nowMs`; or `pubkey-not-allowed`,
// which the shared fixture omits by design (note_on_pubkey_not_allowed). The
// signing test uses a deterministic low-S TestSigner, so it pins
// `signEnvelope`'s clock plumbing and canonicalJson, not a production
// WalletSigner's output.
// ---------------------------------------------------------------------------

const fixturePath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../../../conformance/sdk-envelope/fixtures.json',
);
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  verify_now_ms: number;
  valid_envelope: SignedEnvelope;
  rejection_vectors: Array<{ reason: VerifyEnvelopeReason; envelope: SignedEnvelope }>;
  clock_skew_vectors: Array<{
    _vector_id: string;
    clock_skew_ms: number | null;
    now_ms: number;
    expect_ok: boolean;
    reason?: VerifyEnvelopeReason;
  }>;
  signing_vectors: Array<{
    _vector_id?: string;
    data: Record<string, unknown>;
    nonce: number;
    expiresAt: number;
    expected_payload: string;
    expected_sig: string;
  }>;
};

describe('envelope interop fixture replay under the frozen clock (F-359)', () => {
  it('accepts valid_envelope at verify_now_ms', () => {
    const r = verifyEnvelope({ envelope: fixture.valid_envelope, nowMs: fixture.verify_now_ms });
    expect(r.ok, `reason=${r.reason}`).toBe(true);
    expect(r.reason).toBeUndefined();
  });

  it('rejects every rejection_vectors entry with its listed reason at verify_now_ms', () => {
    expect(fixture.rejection_vectors.length).toBeGreaterThan(0);
    for (const v of fixture.rejection_vectors) {
      const r = verifyEnvelope({ envelope: v.envelope, nowMs: fixture.verify_now_ms });
      expect(r.ok, `expected rejection ${v.reason}`).toBe(false);
      expect(r.reason, `rejection ${v.reason}`).toBe(v.reason);
    }
  });

  it('honors the clock_skew_vectors explicit-zero / not-supplied / override semantics (R-261)', () => {
    expect(fixture.clock_skew_vectors.length).toBeGreaterThan(0);
    for (const v of fixture.clock_skew_vectors) {
      const opts: { envelope: SignedEnvelope; nowMs: number; clockSkewMs?: number } = {
        envelope: fixture.valid_envelope,
        nowMs: v.now_ms,
      };
      if (v.clock_skew_ms !== null) opts.clockSkewMs = v.clock_skew_ms;
      const r = verifyEnvelope(opts);
      if (v.expect_ok) {
        expect(r.ok, `${v._vector_id}: reason=${r.reason}`).toBe(true);
      } else {
        expect(r.ok, `${v._vector_id}: expected ok=false`).toBe(false);
        expect(r.reason, v._vector_id).toBe(v.reason);
      }
    }
  });

  // GAP-064 signing reproduction, through the ACTUAL signEnvelope entry point
  // (not a hand-rolled canonicalJson + sign call): pins the sign-side `nowMs`
  // option, not just verify-side. Before this fix, signEnvelope had no way to
  // pin `nonce` to the fixture's frozen `nonce`/`expiresAt`, so it could only
  // ever sign against the live wall clock and could not reproduce
  // expected_payload/expected_sig byte-for-byte.
  it('signEnvelope with nowMs reproduces each signing_vectors entry byte-for-byte', async () => {
    expect(fixture.signing_vectors.length).toBeGreaterThan(0);
    const signer = new TestSigner(new PrivateKey(1n));
    for (const v of fixture.signing_vectors) {
      const env = await signEnvelope({
        data: v.data,
        signer,
        nowMs: v.nonce,
        ttlMs: v.expiresAt - v.nonce,
      });
      const id = v._vector_id ?? '?';
      expect(env.nonce, id).toBe(v.nonce);
      expect(env.expiresAt, id).toBe(v.expiresAt);
      expect(env.payload, id).toBe(v.expected_payload);
      expect(env.sig, id).toBe(v.expected_sig);
      // The envelope this just produced must also verify at the fixture's
      // frozen verify_now_ms — round-tripping sign and verify through the
      // SAME injectable clock.
      const r = verifyEnvelope({ envelope: env, nowMs: fixture.verify_now_ms });
      expect(r.ok, `${id}: reason=${r.reason}`).toBe(true);
    }
  });
});
