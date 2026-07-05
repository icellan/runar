import { describe, it, expect } from 'vitest';
import { buildWitness } from '../oracle/witness.js';
import { bytesToHex } from '../vm/index.js';

describe('buildWitness', () => {
  it('encodes a positive bigint as a minimal script-number push', () => {
    // 3 → OP push of 0x03
    expect(bytesToHex(buildWitness([3n]))).toBe('0103');
  });

  it('encodes booleans as OP_TRUE / OP_FALSE (0x51 / 0x00)', () => {
    expect(bytesToHex(buildWitness([true]))).toBe('51');
    expect(bytesToHex(buildWitness([false]))).toBe('00');
  });

  it('encodes raw bytes as a length-prefixed push', () => {
    expect(bytesToHex(buildWitness([new Uint8Array([0xde, 0xad])]))).toBe('02dead');
  });

  it('concatenates multiple args in order', () => {
    expect(bytesToHex(buildWitness([3n, 7n]))).toBe('01030107');
  });
});
