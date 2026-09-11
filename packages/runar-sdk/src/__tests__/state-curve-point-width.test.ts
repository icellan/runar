import { describe, it, expect } from 'vitest';
import { serializeState, deserializeState } from '../state.js';
import type { StateField } from 'runar-ir-schema';

/**
 * `P256Point` (64) and `P384Point` (96) are FIXED-WIDTH RAW state fields.
 *
 * All seven compilers emit them as fixed raw slices in the state tail, and
 * `runar-lang`'s cast constructors hard-assert exactly those widths. The seven
 * SDKs used to omit both from their width tables, so they fell through to the
 * push-data default and deployed a state section 1 byte (0x40 direct push) or
 * 2 bytes (OP_PUSHDATA1 0x60) longer than the script's own on-chain reader
 * expects. The deploy succeeded and the FIRST spend failed with
 * `OP_NUMEQUALVERIFY requires the top stack item to be truthy` — funds locked.
 *
 * The `CROSS_SDK_GOLDEN` record below is byte-identical across all seven SDKs;
 * every tier carries the same literal and the same field list.
 */

const FIELDS: StateField[] = [
  { name: 'n', type: 'bigint', index: 0 },
  { name: 'flag', type: 'bool', index: 1 },
  { name: 'pk', type: 'PubKey', index: 2 },
  { name: 'h', type: 'Sha256', index: 3 },
  { name: 'ad', type: 'Addr', index: 4 },
  { name: 'pt', type: 'Point', index: 5 },
  { name: 'p256', type: 'P256Point', index: 6 },
  { name: 'p384', type: 'P384Point', index: 7 },
  { name: 'sig', type: 'Sig', index: 8 },
  { name: 'rab', type: 'RabinSig', index: 9 },
  { name: 'bs', type: 'ByteString', index: 10 },
];

const VALUES: Record<string, unknown> = {
  n: 1n,
  flag: true,
  pk: '02' + 'aa'.repeat(32),
  h: 'bb'.repeat(32),
  ad: 'cc'.repeat(20),
  pt: 'dd'.repeat(64),
  p256: '11'.repeat(64),
  p384: '22'.repeat(96),
  sig: '3044' + 'ee'.repeat(66),
  rab: 'ff'.repeat(8),
  bs: '0011',
};

/** The one wire record every tier must reproduce byte for byte. */
const CROSS_SDK_GOLDEN =
  '0100000000000000' + // bigint 1, NUM2BIN 8
  '01' + //              bool true
  '02' + 'aa'.repeat(32) + // PubKey  33 raw
  'bb'.repeat(32) + //       Sha256   32 raw
  'cc'.repeat(20) + //       Addr     20 raw
  'dd'.repeat(64) + //       Point    64 raw
  '11'.repeat(64) + //       P256Point 64 raw   <- was framed "40" + 64
  '22'.repeat(96) + //       P384Point 96 raw   <- was framed "4c60" + 96
  '44' + '3044' + 'ee'.repeat(66) + // Sig      framed <len><data>
  '08' + 'ff'.repeat(8) + //           RabinSig framed <len><data>
  '02' + '0011'; //                    ByteString framed <len><data>

describe('P256Point / P384Point state field width (TypeScript SDK)', () => {
  it('serializes the cross-SDK golden record byte for byte', () => {
    expect(serializeState(FIELDS, VALUES)).toBe(CROSS_SDK_GOLDEN);
    expect(CROSS_SDK_GOLDEN.length / 2).toBe(399);
  });

  it('deserializes the golden record back to every input value', () => {
    const back = deserializeState(FIELDS, CROSS_SDK_GOLDEN);
    expect(back.n).toBe(1n);
    expect(back.flag).toBe(true);
    for (const k of ['pk', 'h', 'ad', 'pt', 'p256', 'p384', 'sig', 'rab', 'bs']) {
      expect(back[k]).toBe(VALUES[k]);
    }
  });

  it('round-trips a lone P256Point field at 64 raw bytes', () => {
    const fields: StateField[] = [{ name: 'v', type: 'P256Point', index: 0 }];
    const v = '11'.repeat(64);
    const hex = serializeState(fields, { v });
    expect(hex).toBe(v);
    expect(hex.length / 2).toBe(64);
    expect(deserializeState(fields, hex).v).toBe(v);
  });

  it('round-trips a lone P384Point field at 96 raw bytes', () => {
    const fields: StateField[] = [{ name: 'v', type: 'P384Point', index: 0 }];
    const v = '22'.repeat(96);
    const hex = serializeState(fields, { v });
    expect(hex).toBe(v);
    expect(hex.length / 2).toBe(96);
    expect(deserializeState(fields, hex).v).toBe(v);
  });

  it('controls are byte-unchanged: Point/PubKey/Sha256 raw, ByteString/Sig/RabinSig framed', () => {
    const raw: Array<[string, number]> = [
      ['Point', 64],
      ['PubKey', 33],
      ['Sha256', 32],
    ];
    for (const [type, size] of raw) {
      const v = 'ab'.repeat(size);
      expect(serializeState([{ name: 'v', type, index: 0 }], { v })).toBe(v);
    }
    const framed: string[] = ['ByteString', 'Sig', 'RabinSig'];
    for (const type of framed) {
      const v = 'ab'.repeat(64);
      expect(serializeState([{ name: 'v', type, index: 0 }], { v })).toBe('40' + v);
    }
  });
});
