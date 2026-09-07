/**
 * `analyzeScriptHex`'s constant census must count every constant push exactly
 * once, and must stay internally consistent with its own byte categories.
 *
 * The census is not decoration: "the field prime is 71 % of p256-wallet" is the
 * measurement the entire EC constant-pool optimization was justified by, and it
 * comes from this function. Two defects made it undercount, both on the exact
 * byte patterns EC codegen is built from:
 *
 *  (a) A push OVERWROTE the pending `prevPush` without committing it. Only the
 *      opcode branch ever committed one, so back-to-back data pushes recorded
 *      just the last, and `sum(constants.bytes)` disagreed with
 *      `categories['const-push']` in the same returned object.
 *
 *  (b) The PICK/ROLL reclassification then DECREMENTED the constants tally for
 *      a push that (a) had never recorded — subtracting from an unrelated
 *      earlier entry with the same payload, and able to drive counts negative.
 *
 * `push 32; OP_SPLIT` is `decomposePoint`; `push <depth>; OP_PICK` is the new
 * constant pool. A census that miscounts precisely those is measuring the thing
 * it was built to measure incorrectly.
 */

import { describe, it, expect } from 'vitest';
import { analyzeScriptHex } from '../metrics/script-metrics.js';

const PUSH5 = '04aabbccdd';   // OP_PUSH4 aabbccdd  -> 5 bytes
const PUSH32 = '0120';        // OP_PUSH1 0x20      -> 2 bytes
const OP_ADD = '93';
const OP_SPLIT = '7f';
const OP_PICK = '79';
const OP_1 = '51';

function constantFor(hex: string, payload: string) {
  return analyzeScriptHex(hex).constants.find(c => c.hex === payload);
}

describe('analyzeScriptHex constant census', () => {
  it('counts back-to-back identical data pushes separately', () => {
    const c = constantFor(PUSH5 + PUSH5 + OP_ADD, 'aabbccdd');
    expect(c).toEqual({ hex: 'aabbccdd', count: 2, bytes: 10 });
  });

  it('does not lose a data push separated from an opcode by a small int', () => {
    const c = constantFor(PUSH5 + OP_1 + OP_ADD, 'aabbccdd');
    expect(c).toEqual({ hex: 'aabbccdd', count: 1, bytes: 5 });
  });

  it('excludes a PICK/ROLL depth push without disturbing earlier constants', () => {
    // push 32; SPLIT | push 32; SPLIT | push 32; PICK
    // The first two are constants; the third is stack-access cost.
    const hex = PUSH32 + OP_SPLIT + PUSH32 + OP_SPLIT + PUSH32 + OP_PICK;
    expect(constantFor(hex, '20')).toEqual({ hex: '20', count: 2, bytes: 4 });
  });

  it('is order-independent for the same three instructions', () => {
    const a = PUSH32 + OP_SPLIT + PUSH32 + OP_SPLIT + PUSH32 + OP_PICK;
    const b = PUSH32 + OP_PICK + PUSH32 + OP_SPLIT + PUSH32 + OP_SPLIT;
    expect(constantFor(a, '20')).toEqual(constantFor(b, '20'));
  });

  it('never reports a negative count', () => {
    // A PICK whose payload matches an earlier, unrelated constant.
    const hex = PUSH32 + OP_ADD + PUSH32 + OP_PICK + PUSH32 + OP_PICK;
    for (const c of analyzeScriptHex(hex).constants) {
      expect(c.count).toBeGreaterThan(0);
      expect(c.bytes).toBeGreaterThan(0);
    }
  });

  it('keeps sum(constants.bytes) equal to the const-push category', () => {
    // The two must describe the same bytes: anything counted as a constant
    // push is either a constant or reclassified to stack-shuffle, never lost.
    for (const hex of [
      PUSH5 + PUSH5 + OP_ADD,
      PUSH5 + OP_1 + OP_ADD,
      PUSH32 + OP_SPLIT + PUSH32 + OP_SPLIT + PUSH32 + OP_PICK,
      PUSH5 + PUSH32 + OP_PICK + PUSH5 + OP_ADD,
      PUSH5, // trailing push, never confirmed by a following opcode
    ]) {
      const r = analyzeScriptHex(hex);
      const summed = r.constants.reduce((acc, c) => acc + c.bytes, 0);
      expect(summed).toBe(r.categories['const-push']);
    }
  });
});
