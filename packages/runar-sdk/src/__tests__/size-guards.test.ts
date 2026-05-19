import { describe, it, expect } from 'vitest';
import { verifyEnvelope, type SignedEnvelope } from '../envelope.js';
import { InputLimits } from 'runar-ir-schema';

describe('verifyEnvelope size guards', () => {
  it('rejects envelopes whose payload exceeds MAX_IR_BYTES with reason "too-large"', () => {
    const tooBig: SignedEnvelope = {
      payload: 'x'.repeat(InputLimits.MAX_IR_BYTES + 1),
      sig: 'aa',
      pubkey: 'bb',
      nonce: Date.now(),
      expiresAt: Date.now() + 60_000,
    };
    const result = verifyEnvelope({ envelope: tooBig });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('too-large');
  });

  it('rejects envelopes whose sig field exceeds MAX_STRING_BYTES', () => {
    const env: SignedEnvelope = {
      payload: '{}',
      sig: 'a'.repeat(InputLimits.MAX_STRING_BYTES + 1),
      pubkey: 'bb',
      nonce: Date.now(),
      expiresAt: Date.now() + 60_000,
    };
    const result = verifyEnvelope({ envelope: env });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('too-large');
  });

  it('rejects envelopes whose pubkey field exceeds MAX_STRING_BYTES', () => {
    const env: SignedEnvelope = {
      payload: '{}',
      sig: 'aa',
      pubkey: 'b'.repeat(InputLimits.MAX_STRING_BYTES + 1),
      nonce: Date.now(),
      expiresAt: Date.now() + 60_000,
    };
    const result = verifyEnvelope({ envelope: env });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('too-large');
  });

  it('size guards fire before bad-sig / missing-fields', () => {
    // Despite the (junk) sig / pubkey, the size guard runs first.
    const env: SignedEnvelope = {
      payload: 'z'.repeat(InputLimits.MAX_IR_BYTES + 1),
      sig: 'not hex',
      pubkey: 'not hex either',
      nonce: Date.now(),
      expiresAt: Date.now() + 60_000,
    };
    const result = verifyEnvelope({ envelope: env });
    expect(result.reason).toBe('too-large');
  });

  it('passes the size guard for a normally-sized (but bad-sig) envelope', () => {
    // Verifies the guard does not over-reject. Normal-size payload
    // continues past the size guard and lands on a downstream rejection.
    const env: SignedEnvelope = {
      payload: JSON.stringify({ hello: 'world', nonce: 1, expiresAt: 2 }),
      sig: 'aa',
      pubkey: 'bb',
      nonce: 1,
      expiresAt: 2,
    };
    const result = verifyEnvelope({ envelope: env });
    expect(result.ok).toBe(false);
    expect(result.reason).not.toBe('too-large');
  });
});
