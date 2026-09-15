import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BigNumber, Hash, PrivateKey, Utils } from '@bsv/sdk';
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
import { MAX_ENVELOPE_PAYLOAD_DEPTH } from '../envelope.js';
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

  // Finding C4: `outputCount` must size continuation OUTPUTS (byte cost of
  // a locking script), never `estimateCallFee`'s `numFundingInputs` slot
  // (byte cost of a signed P2PKH input, ~148 bytes). The old assertions here
  // called `estimateCallFee(.., outputCount, ..)` — i.e. asserted on the very
  // mis-wiring under test — so they passed even though `estimateFeeForArtifact`
  // was pricing continuation outputs as funding inputs. See
  // c4-fee-for-artifact-output-sizing.test.ts for the independent, built-tx
  // derivation of the correct numbers.
  it('matches estimateCallFee with documented defaults (no funding inputs, 1 output)', () => {
    const expected = estimateCallFee(200, Math.ceil(400 / 4), 0, 0.1 * 1000);
    expect(estimateFeeForArtifact(fakeArtifact)).toBe(expected);
  });

  it('honors feeRate and unlockingScriptLen overrides, sizing extra outputs (not funding inputs)', () => {
    const got = estimateFeeForArtifact(fakeArtifact, { feeRate: 0.5, unlockingScriptLen: 80, outputCount: 2 });
    // 2 continuation outputs: estimateCallFee already prices one 200-byte
    // output; the second is passed as extraOutputBytes (8 + varint(200) + 200
    // = 209 bytes), not as a 148-byte funding input.
    const perOutputSize = 8 + 1 /* varint(200) */ + 200;
    const expected = estimateCallFee(200, 80, 0, 0.5 * 1000, perOutputSize);
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

// ---------------------------------------------------------------------------
// C16 — cross-tier VerifyEnvelopeReason parity.
//
// `verifyEnvelope` is a wire-protocol primitive: per CLAUDE.md all seven SDKs
// must return the SAME `VerifyEnvelopeReason` for the same rejection case.
// The six non-TS tiers all treat an empty payload/sig/pubkey and a zero
// nonce/expiresAt as `missing-fields` at step 1:
//   Go     packages/runar-go/sdk_envelope.go:550
//   Rust   packages/runar-rs/src/sdk/envelope.rs:336
//   Python packages/runar-py/runar/sdk/envelope.py:310
//   Zig    packages/runar-zig/src/sdk_envelope.zig:483
//   Ruby   packages/runar-rb/lib/runar/sdk/envelope.rb:260
//   Java   packages/runar-java/.../sdk/Envelope.java:368
// TS was the outlier: its step-1 check was `typeof`-only, so an empty string
// or a zero nonce slipped through to a LATER reason (or was accepted).
// ---------------------------------------------------------------------------

describe('verifyEnvelope reason parity with the six non-TS tiers (C16)', () => {
  const signer = new TestSigner(ALICE);

  it.each([
    ['payload', (e: SignedEnvelope) => ({ ...e, payload: '' })],
    ['sig', (e: SignedEnvelope) => ({ ...e, sig: '' })],
    ['pubkey', (e: SignedEnvelope) => ({ ...e, pubkey: '' })],
  ])('rejects an empty %s with missing-fields', async (_field, mutate) => {
    const env = await signEnvelope({ data: { ok: 1 }, signer });
    const r = verifyEnvelope({ envelope: mutate(env) });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('missing-fields');
  });

  it('rejects a zero nonce with missing-fields', async () => {
    // Sign a well-formed envelope whose inner payload also carries nonce 0, so
    // the only thing distinguishing it from a valid envelope is the zero nonce
    // itself (it would otherwise reach envelope-mismatch / bad-sig / ok).
    const nonce = 0;
    const expiresAt = Date.now() + 30_000;
    const payload = canonicalJson({ ok: 1, nonce, expiresAt });
    const digest = Hash.sha256(Utils.toArray(payload, 'utf8'));
    const env: SignedEnvelope = {
      payload,
      sig: await signer.signHash(digest),
      pubkey: await signer.getPublicKey(),
      nonce,
      expiresAt,
    };
    const r = verifyEnvelope({ envelope: env });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('missing-fields');
  });

  it('rejects a zero expiresAt with missing-fields (not expired)', async () => {
    const nonce = Date.now();
    const expiresAt = 0;
    const payload = canonicalJson({ ok: 1, nonce, expiresAt });
    const digest = Hash.sha256(Utils.toArray(payload, 'utf8'));
    const env: SignedEnvelope = {
      payload,
      sig: await signer.signHash(digest),
      pubkey: await signer.getPublicKey(),
      nonce,
      expiresAt,
    };
    const r = verifyEnvelope({ envelope: env });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('missing-fields');
  });

  it('agrees with the committed cross-tier missing-fields rejection vector', () => {
    // conformance/sdk-envelope/fixtures.json is the frozen wire fixture the six
    // non-TS tiers replay. Its `missing-fields` vector carries `sig: ""` — an
    // EMPTY string, not an absent field — which is exactly the case TS used to
    // wave through. missing-fields is checked before expiry, so this vector
    // replays deterministically without an injectable clock.
    const fixturePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      '../../../../conformance/sdk-envelope/fixtures.json',
    );
    const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
      rejection_vectors: Array<{ reason: string; envelope: SignedEnvelope }>;
    };
    const vector = fixture.rejection_vectors.find((v) => v.reason === 'missing-fields');
    expect(vector, 'fixtures.json must carry a missing-fields rejection vector').toBeDefined();
    expect(vector!.envelope.sig).toBe('');

    const r = verifyEnvelope({ envelope: vector!.envelope });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('missing-fields');
  });

  // R-115 / CL-BUG-066. The fixture's `v23-lone-surrogate-payload-bad-json`
  // vector covers the six tiers whose verify takes an injectable clock; the TS
  // verify reads `Date.now()` directly, so it gets the same envelope built
  // around a live clock instead.
  it('rejects a payload containing an unpaired surrogate with bad-json', () => {
    const now = Date.now();
    const payload = `{"expiresAt":${now + 60_000},"msg":"x\\ud800y","nonce":${now}}`;
    const r = verifyEnvelope({
      envelope: {
        payload,
        sig: '30'.repeat(36),
        pubkey: `02${'ab'.repeat(32)}`,
        nonce: now,
        expiresAt: now + 60_000,
      },
    });
    expect(r.ok).toBe(false);
    // Before the fix this was 'bad-sig': JSON.parse accepted the unpaired
    // surrogate and the run fell through to the signature check, while rust,
    // ruby and zig had already rejected the same bytes as bad JSON.
    expect(r.reason).toBe('bad-json');
  });

  it('still accepts a payload whose surrogates are correctly PAIRED', () => {
    const now = Date.now();
    // U+1F600, spelled as the surrogate pair \ud83d\ude00 — legal JSON, legal
    // Unicode, and it must not be caught by the lone-surrogate guard.
    const payload = `{"expiresAt":${now + 60_000},"msg":"\\ud83d\\ude00","nonce":${now}}`;
    const r = verifyEnvelope({
      envelope: {
        payload,
        sig: '30'.repeat(36),
        pubkey: `02${'ab'.repeat(32)}`,
        nonce: now,
        expiresAt: now + 60_000,
      },
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad-sig');
  });
});

// ---------------------------------------------------------------------------
// R-260 — shared payload nesting bound.
//
// `verifyEnvelope` parses the payload with each tier's stock JSON library and
// used to inherit that library's recursion cap. Measured on ONE envelope
// (priv=1, live clock, payload `{"deep":<N-deep array>,…}`):
//
//   ts / go / python / zig   accepted every depth probed (zig to 100001)
//   ruby                     bad-json from total depth 101 (JSON.parse
//                            max_nesting: 100)
//   rust                     bad-json from total depth 128 (serde_json
//                            RECURSION_LIMIT)
//   java                     StackOverflowError thrown OUT of verify at ~5000
//                            deep on a default JVM stack and ~1000 under
//                            -Xss512k — i.e. a contract escape on
//                            unauthenticated input, at a threshold set by a
//                            JVM launch flag rather than by the protocol
//
// Every tier now enforces MAX_ENVELOPE_PAYLOAD_DEPTH on the payload TEXT with
// a NON-RECURSIVE bracket scan run before the stock parser, so the answer is
// the same everywhere and the guard itself cannot overflow. TS's verify reads
// `Date.now()` directly rather than taking an injectable clock, so — as with
// the R-115 lone-surrogate vector — it replays the fixture's SHAPE around a
// live clock instead of the fixture's frozen envelope.
// ---------------------------------------------------------------------------

describe('verifyEnvelope payload depth bound (R-260)', () => {
  const signer = new TestSigner(ALICE);

  /** An N-deep array: nest(3) === [[[0]]]. */
  function nest(n: number): unknown {
    let v: unknown = 0;
    for (let i = 0; i < n; i++) v = [v];
    return v;
  }

  async function signAtArrayDepth(arrays: number): Promise<SignedEnvelope> {
    const nonce = Date.now();
    const expiresAt = nonce + 60_000;
    // canonicalJson's own nesting cap is 512, well clear of these depths.
    const payload = canonicalJson({ deep: nest(arrays), nonce, expiresAt });
    const digest = Hash.sha256(Utils.toArray(payload, 'utf8'));
    return {
      payload,
      sig: await signer.signHash(digest),
      pubkey: await signer.getPublicKey(),
      nonce,
      expiresAt,
    };
  }

  it('accepts a payload exactly at the limit', async () => {
    // 1 outer object + 63 arrays = MAX_ENVELOPE_PAYLOAD_DEPTH. This is the
    // control with teeth: an over-strict or off-by-one guard reddens here.
    const env = await signAtArrayDepth(MAX_ENVELOPE_PAYLOAD_DEPTH - 1);
    const r = verifyEnvelope({ envelope: env });
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  });

  it('rejects a payload one level past the limit with bad-json', async () => {
    // Signed VALIDLY, so a tier that fails to enforce the bound returns
    // ok:true rather than some other rejection — this cannot pass by accident
    // on a bad-sig fallthrough.
    const env = await signAtArrayDepth(MAX_ENVELOPE_PAYLOAD_DEPTH);
    const r = verifyEnvelope({ envelope: env });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad-json');
  });

  it('rejects a payload deep enough to overflow a recursive parser', () => {
    // ~10 KB of brackets — the shape that threw StackOverflowError out of the
    // Java tier's verify. The guard is a flat scan, so no tier recurses here.
    const nonce = Date.now();
    const expiresAt = nonce + 60_000;
    const payload = `{"deep":${'['.repeat(5000)}0${']'.repeat(5000)},"expiresAt":${expiresAt},"nonce":${nonce}}`;
    const r = verifyEnvelope({
      envelope: { payload, sig: '30'.repeat(36), pubkey: `02${'ab'.repeat(32)}`, nonce, expiresAt },
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad-json');
  });

  it('still accepts a brace or bracket that only appears inside a string', async () => {
    // The scan must skip string contents, or an ordinary message value like
    // "{{{{…" would be counted as nesting and rejected.
    const nonce = Date.now();
    const expiresAt = nonce + 60_000;
    const payload = canonicalJson({ msg: '['.repeat(200) + '{'.repeat(200), nonce, expiresAt });
    const digest = Hash.sha256(Utils.toArray(payload, 'utf8'));
    const r = verifyEnvelope({
      envelope: {
        payload,
        sig: await signer.signHash(digest),
        pubkey: await signer.getPublicKey(),
        nonce,
        expiresAt,
      },
    });
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  });

  it('pins MAX_ENVELOPE_PAYLOAD_DEPTH to the cross-tier fixture', () => {
    const fixturePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      '../../../../conformance/sdk-envelope/fixtures.json',
    );
    const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as { payload_depth_limit: number };
    expect(fixture.payload_depth_limit).toBe(MAX_ENVELOPE_PAYLOAD_DEPTH);
  });
});
