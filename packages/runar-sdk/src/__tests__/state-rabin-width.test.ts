/**
 * F-035: `RabinPubKey` / `RabinSig` state fields are a bare 8-byte OP_NUM2BIN
 * word, exactly like `bigint`, in the shared width table and in the TS state
 * codec.
 *
 * Both types are bigint aliases (`packages/runar-lang/src/types.ts`), and every
 * compiler writes and reads them in the state section as `bigint`: OP_NUM2BIN 8
 * on write, an 8-byte slice + OP_BIN2NUM on read (05-stack-lower.ts). The
 * compiler is canonical here (user decision D2). The shared `STATE_FIELD_WIDTHS`
 * table and the SDK codec omitted both types, so they fell to the push-data
 * branch. For a bigint value that meant `String(5n)` framed as hex — `0.85`-style
 * garbage — and a state section the compiled script cannot read.
 *
 * Expected bytes are derived BY HAND from the num2bin-le8 encoding (8 bytes,
 * little-endian magnitude, sign in 0x80 of byte 7), never read off the
 * serializer:
 *
 *   0x1234567890ABCDEF  -> ef cd ab 90 78 56 34 12
 *   -1000000007         -> 1000000007 = 0x3B9ACA07 -> 07 ca 9a 3b 00 00 00 80
 *   3                   -> 03 00 00 00 00 00 00 00
 *
 * The same three values are the `state-rabin` sdk-output fixture, whose
 * expected-locking.hex all seven SDKs must reproduce byte for byte.
 *
 * What this proves: the shared table declares both types num2bin-le8 / 8 bytes;
 * the TS writer emits those exact bytes (no push prefix) at the right offsets;
 * the TS reader reads them back; the compiler's artifact annotates the fields
 * with that layout. What it does NOT prove: that the compiled script accepts
 * the bytes — that is the Spend proof in
 * packages/runar-testing/src/__tests__/f035-rabin-state-spend.test.ts — or
 * anything about the other six SDKs (each has its own test, plus sdk-output).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile } from 'runar-compiler';
import { STATE_FIELD_WIDTHS } from 'runar-ir-schema';
import type { StateField } from 'runar-ir-schema';
import { serializeState, deserializeState } from '../state.js';

const FIELDS: StateField[] = [
  { name: 'oracleKey', type: 'RabinPubKey', index: 0 },
  { name: 'lastSig', type: 'RabinSig', index: 1 },
  { name: 'count', type: 'bigint', index: 2 },
];

const VALUES = { oracleKey: 0x1234567890abcdefn, lastSig: -1000000007n, count: 3n };
const EXPECTED = 'efcdab9078563412' + '07ca9a3b00000080' + '0300000000000000';

describe('F-035: RabinPubKey / RabinSig are 8-byte num2bin state fields', () => {
  it('the shared STATE_FIELD_WIDTHS table declares both as num2bin-le8, 8 bytes', () => {
    expect(STATE_FIELD_WIDTHS.RabinPubKey).toEqual({ size: 8, encoding: 'num2bin-le8' });
    expect(STATE_FIELD_WIDTHS.RabinSig).toEqual({ size: 8, encoding: 'num2bin-le8' });
  });

  it('serializeState writes the hand-derived bytes, no push prefix', () => {
    expect(serializeState(FIELDS, VALUES)).toBe(EXPECTED);
  });

  it('deserializeState reads them back', () => {
    expect(deserializeState(FIELDS, EXPECTED)).toEqual(VALUES);
  });

  it('a Rabin value that does not fit the 8-byte word is refused, like bigint', () => {
    expect(() => serializeState(FIELDS, { ...VALUES, oracleKey: 1n << 63n })).toThrow(/does not fit/);
  });

  it('the compiler annotates the fields with the same layout', () => {
    const src = readFileSync(
      join(__dirname, '..', '..', '..', '..', 'conformance', 'sdk-output', 'contracts', 'RabinState.runar.ts'),
      'utf8',
    );
    const r = compile(src, { fileName: 'RabinState.runar.ts' });
    expect(r.success).toBe(true);
    const sf = r.artifact!.stateFields!;
    expect(sf.map((f) => [f.name, f.encoding, f.byteLength, f.byteOffset])).toEqual([
      ['oracleKey', 'num2bin-le8', 8, 0],
      ['lastSig', 'num2bin-le8', 8, 8],
      ['count', 'num2bin-le8', 8, 16],
    ]);
  });
});
