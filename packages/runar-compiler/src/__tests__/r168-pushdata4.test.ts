/**
 * R-168: the compiler must read OP_PUSHDATA4 (`0x4e`) the SDKs emit.
 *
 * encodePushData already writes 0x4e for payloads ≥ 65536. A decoder that
 * only understood direct / PUSHDATA1 / PUSHDATA2 treated 0x4e as length 78
 * and desynchronised every later field. This drives the shipped
 * encodePushData / decodePushData pair, not a copy.
 */
import { describe, it, expect } from 'vitest';
import { encodePushData, decodePushData } from '../passes/push-encoding.js';

function roundTrip(len: number): void {
  const payload = new Uint8Array(len);
  for (let i = 0; i < len; i++) payload[i] = i & 0xff;
  const encoded = encodePushData(payload);
  const { data, next } = decodePushData(encoded, 0);
  expect(next, `did not consume whole encoding at len=${len}`).toBe(encoded.length);
  expect(data, `payload mismatch at len=${len}`).toEqual(payload);
}

describe('R-168: compiler reads OP_PUSHDATA4 the SDKs emit', () => {
  it('encodePushData uses 0x4e for a 65536-byte payload', () => {
    const encoded = encodePushData(new Uint8Array(65536));
    expect(encoded[0]).toBe(0x4e);
    expect(encoded.length).toBe(5 + 65536);
  });

  it('decodePushData round-trips a 65536-byte OP_PUSHDATA4 encoding', () => {
    roundTrip(65536);
  });

  it('decodePushData round-trips the smaller encodings too', () => {
    roundTrip(0);
    roundTrip(1);
    roundTrip(75);
    roundTrip(76);
    roundTrip(255);
    roundTrip(256);
    roundTrip(65535);
  });

  it('decodePushData refuses a truncated 0x4e header', () => {
    expect(() => decodePushData(Uint8Array.of(0x4e, 0x01, 0x00))).toThrow(/PUSHDATA4/);
  });
});
