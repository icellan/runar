/**
 * A missing value for a raw fixed-width state field must refuse, not stringify.
 *
 * `encodeStateValue`'s raw arm did `String(value)`. For `undefined` that writes
 * the literal nine characters `undefined` where the artifact declares a
 * 33-byte PubKey — not hex, not the right width, and silent.
 *
 * Six SDKs were fixed to refuse this (Go/Rust panic per their documented
 * serialize contract, Python `ValueError`, Ruby `ArgumentError`, Java
 * `IllegalArgumentException`, Zig `error.MissingStateValue`). That left
 * TypeScript — the reference implementation — as the only tier still writing
 * garbage, so the fix created a 1-vs-6 divergence on a wire-format primitive.
 * This closes it.
 *
 * Scoped to the raw fixed-width arm on purpose. The variable-length branch
 * treats an empty value as `OP_0`, which is legitimate and unchanged: an empty
 * ByteString is a real state value, a missing PubKey is not.
 */

import { describe, it, expect } from 'vitest';
import { serializeState } from '../state.js';
import type { StateField } from 'runar-ir-schema';

const field = (name: string, type: string): StateField =>
  ({ name, type, index: 0 }) as unknown as StateField;

describe('C-2: a missing raw fixed-width state value is refused', () => {
  for (const [type, width] of [
    ['PubKey', 33],
    ['Sha256', 32],
    ['Ripemd160', 20],
    ['Addr', 20],
    ['Point', 64],
    ['P256Point', 64],
    ['P384Point', 96],
  ] as const) {
    it(`refuses a missing ${type} rather than writing "undefined"`, () => {
      expect(() => serializeState([field('k', type)], {})).toThrow(
        /state field "k"|missing|required/i,
      );
    });

    it(`refuses an explicit null ${type}`, () => {
      expect(() =>
        serializeState([field('k', type)], { k: null } as Record<string, unknown>),
      ).toThrow(/state field "k"|missing|required/i);
    });

    it(`still accepts a well-formed ${type} of ${width} bytes`, () => {
      const hex = 'ab'.repeat(width);
      expect(serializeState([field('k', type)], { k: hex })).toBe(hex);
    });
  }

  it('leaves the variable-length arm alone — an empty ByteString is still OP_0', () => {
    expect(serializeState([field('m', 'ByteString')], { m: '' })).toBe('00');
  });

  it('leaves a populated ByteString alone', () => {
    expect(serializeState([field('m', 'ByteString')], { m: 'deadbeef' })).toBe('04deadbeef');
  });
});
