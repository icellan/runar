import { describe, it, expect } from 'vitest';
import { BigNumber, Hash, PrivateKey, Utils } from '@bsv/sdk';
import { sign as ecdsaSignRaw } from '@bsv/sdk/primitives/ECDSA';
import { verifyEnvelope } from '../envelope.js';
import type { SignedEnvelope } from '../envelope.js';

// ---------------------------------------------------------------------------
// GK-BUG-009: the payload's own nonce / expiresAt must be a JSON INTEGER TOKEN
// (optional '-', then 0 or a non-zero digit and digits; no '.', no exponent,
// inside the signed 64-bit range, not a boolean). Anything else is
// envelope-mismatch in all seven tiers.
//
// JSON.parse erases the token spelling (1.0, 1e0 and 1 all become the number
// 1), so TS decides this on the payload TEXT, the way R-115 / R-260 do. The
// cross-tier vectors live in conformance/sdk-envelope/fixtures.json
// (rejection_vectors it1..it8); this file pins the scanner's own edge cases:
// key escapes, duplicate keys, whitespace, nesting, and the i64 boundary.
//
// Test proves: verifyEnvelope's step 4 reads the same top-level member
// JSON.parse reads and rejects every non-integer spelling of it, and accepts
// an integer token at the i64 boundary. Every envelope is validly signed for
// its exact payload text, so a wrong accept shows as ok:true, not bad-sig.
// Test does not prove: the other six tiers (fixture replay in each tier's
// interop test does that).
// ---------------------------------------------------------------------------

const ALICE = new PrivateKey(1);
const ALICE_PUB = ALICE.toPublicKey().toDER('hex') as string;
const NOW = 1_700_000_000_500;

function signed(payload: string, nonce: number, expiresAt: number): SignedEnvelope {
  const digest = Hash.sha256(Utils.toArray(payload, 'utf8'));
  const sig = ecdsaSignRaw(new BigNumber(digest), ALICE as unknown as BigNumber, true);
  return {
    payload,
    sig: Utils.toHex(sig.toDER() as number[]),
    pubkey: ALICE_PUB,
    nonce,
    expiresAt,
  };
}

const EXP = 1_700_000_030_000;

describe('GK-BUG-009: inner nonce/expiresAt must be a JSON integer token', () => {
  it('accepts plain integer tokens (control)', () => {
    const r = verifyEnvelope({
      envelope: signed(`{"expiresAt":${EXP},"kind":"x","nonce":7}`, 7, EXP),
      nowMs: NOW,
    });
    expect(r.ok, `reason=${r.reason}`).toBe(true);
  });

  it('accepts JSON whitespace around the members (control)', () => {
    const r = verifyEnvelope({
      envelope: signed(`{ "expiresAt" :\t${EXP} ,\n"nonce"\r: 7 }`, 7, EXP),
      nowMs: NOW,
    });
    expect(r.ok, `reason=${r.reason}`).toBe(true);
  });

  it('accepts the i64 maximum as an integer token (boundary control)', () => {
    const tok = '9223372036854775807';
    const r = verifyEnvelope({
      envelope: signed(`{"expiresAt":${EXP},"nonce":${tok}}`, Number(tok), EXP),
      nowMs: NOW,
    });
    expect(r.ok, `reason=${r.reason}`).toBe(true);
  });

  it('rejects an integer token one past the i64 maximum', () => {
    // JSON.parse rounds both 2^63-1 and 2^63 to the same double, so only the
    // token range check can tell them apart.
    const r = verifyEnvelope({
      envelope: signed(`{"expiresAt":${EXP},"nonce":9223372036854775808}`, Number('9223372036854775807'), EXP),
      nowMs: NOW,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('envelope-mismatch');
  });

  it.each([
    ['1.0', 1],
    ['1e0', 1],
    ['1E0', 1],
    ['10e-1', 1],
    ['-1.0', -1],
  ])('rejects the non-integer spelling %s of nonce', (tok, outer) => {
    const r = verifyEnvelope({
      envelope: signed(`{"expiresAt":${EXP},"nonce":${tok}}`, outer, EXP),
      nowMs: NOW,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('envelope-mismatch');
  });

  it('rejects a non-integer expiresAt behind a key written with escapes', () => {
    // "expiresAt" spelled with \\u escapes is the same key to JSON.parse.
    const r = verifyEnvelope({
      envelope: signed(`{"\\u0065xpiresAt":${EXP}.0,"nonce":7}`, 7, EXP),
      nowMs: NOW,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('envelope-mismatch');
  });

  it('reads the LAST duplicate member, as JSON.parse does', () => {
    const lastBad = verifyEnvelope({
      envelope: signed(`{"expiresAt":${EXP},"nonce":7,"nonce":7.0}`, 7, EXP),
      nowMs: NOW,
    });
    expect(lastBad.ok).toBe(false);
    expect(lastBad.reason).toBe('envelope-mismatch');

    const lastGood = verifyEnvelope({
      envelope: signed(`{"expiresAt":${EXP},"nonce":7.0,"nonce":7}`, 7, EXP),
      nowMs: NOW,
    });
    expect(lastGood.ok, `reason=${lastGood.reason}`).toBe(true);
  });

  it('ignores nested members and string contents named nonce', () => {
    const r = verifyEnvelope({
      envelope: signed(
        `{"a":{"nonce":1.5},"b":["\\"nonce\\":1.5",{"expiresAt":1e3}],"expiresAt":${EXP},"nonce":7}`,
        7,
        EXP,
      ),
      nowMs: NOW,
    });
    expect(r.ok, `reason=${r.reason}`).toBe(true);
  });
});
