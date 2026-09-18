import { describe, it, expect } from 'vitest';
import { serializeState, deserializeState } from '../state.js';
import type { StateField } from 'runar-ir-schema';

/**
 * A mutable `boolean` state field is ONE raw byte — `01` or `00`.
 *
 * The compiler spells the type `boolean`. `bool` appears nowhere in any of the
 * seven frontends, so an artifact's `stateFields` never carries it; the SDKs
 * that matched on `bool` alone were matching a spelling no compiler emits, and
 * every real boolean field fell through to their push-data default:
 *
 *     typescript  01           correct
 *     ruby        01           correct
 *     go          02 74727565  push-framed ASCII "true" — 3 bytes too long
 *     java        02 74727565  same
 *     python      00           right width, ALWAYS false
 *     zig         00           same
 *     rust        panic        as_bytes() on a Bool variant
 *
 * All five are fund-affecting. Go and Java deploy a state tail longer than the
 * one the script's own reader rebuilds, so `hash256(outputs)` can never match
 * and the first spend is impossible. Python and Zig deploy a well-formed tail
 * that says `false` whatever the caller passed, so the first call that sets the
 * flag builds a continuation the covenant rejects. Rust fails closed.
 *
 * `BOOLEAN_SPELLING_GOLDEN` is byte-identical across all seven SDKs; every tier
 * carries the same literal and the same field list. The trailing `bigint` is
 * load-bearing: a boolean of the wrong WIDTH shifts it, so the record catches a
 * length error that a lone boolean field would hide.
 */

const FIELDS: StateField[] = [
  { name: 'count', type: 'bigint', index: 0 },
  // The canonical spelling — the only one any compiler emits.
  { name: 'flag', type: 'boolean', index: 1 },
  // The alias. Several tiers accepted only this one; it must keep working.
  { name: 'alias', type: 'bool', index: 2 },
  { name: 'tail', type: 'bigint', index: 3 },
];

/** The one wire record every tier must reproduce byte for byte. */
const BOOLEAN_SPELLING_GOLDEN =
  '0700000000000000' + // bigint 7, NUM2BIN 8
  '01' + //              boolean true  — 1 raw byte
  '00' + //              bool    false — 1 raw byte
  '0100000000000000'; //  bigint 1, NUM2BIN 8

const FLIPPED_GOLDEN =
  '0700000000000000' + '00' + '01' + '0100000000000000';

describe('boolean state fields are one raw byte under either spelling', () => {
  it('serializes the cross-SDK golden record byte for byte', () => {
    expect(BOOLEAN_SPELLING_GOLDEN.length / 2).toBe(18);
    expect(
      serializeState(FIELDS, { count: 7n, flag: true, alias: false, tail: 1n }),
    ).toBe(BOOLEAN_SPELLING_GOLDEN);
  });

  it('serializes the opposite polarity, so a constant answer cannot pass', () => {
    expect(
      serializeState(FIELDS, { count: 7n, flag: false, alias: true, tail: 1n }),
    ).toBe(FLIPPED_GOLDEN);
  });

  it('deserializes the golden record back to every input value', () => {
    const back = deserializeState(FIELDS, BOOLEAN_SPELLING_GOLDEN);
    expect(back.count).toBe(7n);
    expect(back.flag).toBe(true);
    expect(back.alias).toBe(false);
    expect(back.tail).toBe(1n);
  });

  it('deserializes the flipped record too', () => {
    const back = deserializeState(FIELDS, FLIPPED_GOLDEN);
    expect(back.flag).toBe(false);
    expect(back.alias).toBe(true);
  });

  it('encodes a lone `boolean` field as exactly one byte', () => {
    const one: StateField[] = [{ name: 'v', type: 'boolean', index: 0 }];
    expect(serializeState(one, { v: true })).toBe('01');
    expect(serializeState(one, { v: false })).toBe('00');
    expect(deserializeState(one, '01').v).toBe(true);
    expect(deserializeState(one, '00').v).toBe(false);
  });
});
