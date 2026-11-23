import { describe, it, expect } from 'vitest';
import { reverseBytes } from '../runtime/builtins.js';
import type { ByteString } from '../types.js';

// Since D12 BM-F3 every compiler's reverseBytes ends in `OP_0 OP_EQUALVERIFY`,
// so the script ABORTS on an input longer than 520 bytes. The native runtime
// must refuse the same input rather than hand the contract test a full reverse
// the network would never compute.
const bytes = (n: number): ByteString =>
  Array.from({ length: n }, (_, i) => (i % 256).toString(16).padStart(2, '0')).join('') as ByteString;
const rev = (h: string): string => (h.match(/../g) ?? []).reverse().join('');

describe('reverseBytes 520-byte bound (native runtime)', () => {
  for (const n of [0, 1, 520]) {
    it(`reverses ${n} bytes`, () => {
      expect(reverseBytes(bytes(n))).toBe(rev(bytes(n)));
    });
  }
  it('refuses 521 bytes', () => {
    expect(() => reverseBytes(bytes(521))).toThrow(/520/);
  });
});
