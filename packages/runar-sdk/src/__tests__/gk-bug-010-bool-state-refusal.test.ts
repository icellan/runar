/**
 * GK-BUG-010 — a boolean state field accepts only a real boolean.
 *
 * bool / boolean state fields are one raw byte, 01 or 00. Every tier encoded a
 * NON-boolean value by its own coercion rule: TS/Python/Ruby truthiness (so 0
 * and 'false' wrote 01 in Ruby), Go and Java "anything but true is 00", Zig
 * `.int` != 0, Rust a panic. The same input gave different on-chain bytes per
 * tier. Now every tier refuses a non-boolean with a named error, the way the
 * num2bin arm (N-084) refuses a non-integer.
 *
 * What it proves: serializeState throws for 0, 1, 0n, 1n, 'true', 'false', '',
 * '01', null and undefined in both spellings of the type, and true / false
 * still encode as 01 / 00.
 * What it does not prove: anything on chain; the other six SDKs (each has its
 * own gk-bug-010 test).
 */

import { describe, it, expect } from 'vitest';
import type { StateField } from 'runar-ir-schema';
import { serializeState } from '../state.js';

const TYPES = ['bool', 'boolean'];

const field = (type: string): StateField =>
  ({ name: 'flag', type, index: 0 }) as unknown as StateField;

describe('GK-BUG-010: boolean state fields refuse a non-boolean value', () => {
  const bad: [string, unknown][] = [
    ['0', 0],
    ['1', 1],
    ['0n', 0n],
    ['1n', 1n],
    ["'true'", 'true'],
    ["'false'", 'false'],
    ['empty string', ''],
    ["'01'", '01'],
    ['null', null],
    ['undefined', undefined],
  ];
  for (const type of TYPES) {
    for (const [name, value] of bad) {
      it(`${type}: refuses ${name}`, () => {
        expect(() => serializeState([field(type)], { flag: value })).toThrow(
          new RegExp(`state field "flag" \\(${type}\\) must be a boolean`),
        );
      });
    }
    it(`${type}: true / false keep their bytes`, () => {
      expect(serializeState([field(type)], { flag: true })).toBe('01');
      expect(serializeState([field(type)], { flag: false })).toBe('00');
    });
  }
});
