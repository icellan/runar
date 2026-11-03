/**
 * N-084 — the num2bin state encode path fails closed.
 *
 * bigint / int / RabinSig / RabinPubKey state fields are written as an 8-byte
 * OP_NUM2BIN word. A value that is not an integer (or a decimal integer
 * string, with the optional JSON "n" suffix) must be refused with a named
 * error, never coerced: BigInt(true) is 1n, BigInt('') and BigInt('  ') are
 * 0n, BigInt('0x10') is 16n. Each of those silently wrote a number the caller
 * never supplied into a state section that is committed on chain.
 *
 * What it proves: serializeState throws for a bool, '', a hex string, a
 * non-decimal string, a float, null/undefined and a byte array in each of the
 * four num2bin types, and that valid integers keep their exact bytes.
 * What it does not prove: anything on chain; the other six SDKs (each has its
 * own n084 test).
 */

import { describe, it, expect } from 'vitest';
import type { StateField } from 'runar-ir-schema';
import { serializeState } from '../state.js';

const TYPES = ['int', 'bigint', 'RabinSig', 'RabinPubKey'];

const field = (type: string): StateField =>
  ({ name: 'k', type, index: 0 }) as unknown as StateField;

describe('N-084: num2bin state fields refuse a non-integer value', () => {
  const bad: [string, unknown][] = [
    ['true', true],
    ['empty string', ''],
    ['blank string', '  '],
    ['hex string 0x10', '0x10'],
    ['hex digits', 'deadbeef'],
    ['non-decimal string', 'abc'],
    ['float', 1.5],
    ['NaN', Number.NaN],
    ['null', null],
    ['undefined', undefined],
    ['byte array', new Uint8Array([1, 2])],
  ];
  for (const type of TYPES) {
    for (const [name, value] of bad) {
      it(`${type}: refuses ${name}`, () => {
        expect(() => serializeState([field(type)], { k: value })).toThrow(
          new RegExp(`state field "k" \\(${type}\\) must be an integer`),
        );
      });
    }
    it(`${type}: valid integers keep their bytes`, () => {
      expect(serializeState([field(type)], { k: 0n })).toBe('0000000000000000');
      expect(serializeState([field(type)], { k: 5n })).toBe('0500000000000000');
      expect(serializeState([field(type)], { k: -5n })).toBe('0500000000000080');
      expect(serializeState([field(type)], { k: 5 })).toBe('0500000000000000');
      expect(serializeState([field(type)], { k: '5' })).toBe('0500000000000000');
      expect(serializeState([field(type)], { k: '5n' })).toBe('0500000000000000');
      expect(serializeState([field(type)], { k: '-5n' })).toBe('0500000000000080');
    });
  }
});
