/**
 * Minimal test for add32 in Bitcoin Script using BSV SDK Spend interpreter.
 * Isolates the byte reversal + BIN2NUM + ADD + MOD + NUM2BIN approach.
 */
import { describe, it, expect } from 'vitest';
import { LockingScript, UnlockingScript, Spend } from '@bsv/sdk';

function runScript(lockingHex: string, unlockingHex: string): { success: boolean; error?: string } {
  const lockingScript = LockingScript.fromHex(lockingHex);
  const unlockingScript = UnlockingScript.fromHex(unlockingHex);
  const spend = new Spend({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: 100000,
    lockingScript,
    transactionVersion: 2,
    otherInputs: [],
    outputs: [],
    unlockingScript,
    inputIndex: 0,
    inputSequence: 0xffffffff,
    lockTime: 0,
  });
  try {
    const ok = spend.validate();
    return { success: ok };
  } catch (e: unknown) {
    return { success: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Build hex for: push <bytes> */
function pushData(hex: string): string {
  const bytes = hex.length / 2;
  if (bytes <= 75) {
    return bytes.toString(16).padStart(2, '0') + hex;
  }
  throw new Error('pushData > 75 bytes not implemented');
}

describe('add32 isolation test', () => {
  it('reverseBytes4: reverses 4 bytes', () => {
    // Push 0x6a09e667, then reverse to 0x67e6096a
    // reverseBytes4: 3x (push 1, SPLIT) + 3x (SWAP, CAT)
    const reverseBytes4 =
      '51' + '7f' +  // OP_1 OP_SPLIT
      '51' + '7f' +  // OP_1 OP_SPLIT
      '51' + '7f' +  // OP_1 OP_SPLIT
      '7c' + '7e' +  // OP_SWAP OP_CAT
      '7c' + '7e' +  // OP_SWAP OP_CAT
      '7c' + '7e';   // OP_SWAP OP_CAT

    // Locking script: reverseBytes4 + push expected + OP_EQUAL
    const locking = reverseBytes4 + pushData('67e6096a') + '87';
    // Unlocking: push 0x6a09e667
    const unlocking = pushData('6a09e667');

    const result = runScript(locking, unlocking);
    if (!result.success) console.log('reverseBytes4 ERROR:', result.error);
    expect(result.success).toBe(true);
  });

  it('be2num: converts BE 4-byte to unsigned number', () => {
    // be2num: reverseBytes4 + push 0x00 + CAT + BIN2NUM
    const reverseBytes4 =
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';
    const be2num = reverseBytes4 + pushData('00') + '7e' + '81';

    // 0x6a09e667 = 1779033703
    // As LE script number: 0x67e6096a (4 bytes, MSB of last byte = 0, positive)
    // BIN2NUM should strip the padding 0x00 since last byte of 0x6a is < 0x80
    // Push the expected number and check equality
    const expectedNum = pushData('67e6096a'); // 1779033703 as LE script number

    // Actually let's use OP_NUMEQUAL (0x9c)
    const lockingSimple = be2num + expectedNum + '9c'; // OP_NUMEQUAL
    const unlocking = pushData('6a09e667');

    const result = runScript(lockingSimple, unlocking);
    if (!result.success) console.log('be2num ERROR:', result.error);
    expect(result.success).toBe(true);
  });

  it('be2num: converts 0x80000000 (value >= 2^31) correctly', () => {
    const reverseBytes4 =
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';
    const be2num = reverseBytes4 + pushData('00') + '7e' + '81';

    // 0x80000000 = 2147483648
    // LE bytes: 0x00000080
    // With padding: 0x0000008000 (5 bytes)
    // BIN2NUM: last byte 0x00, previous byte 0x80 (MSB=1) → can't strip padding
    // So remains 5-byte number: 0x0000008000
    const expectedNum = pushData('0000008000'); // 2147483648 as LE script number

    const locking = be2num + expectedNum + '9c'; // OP_NUMEQUAL
    const unlocking = pushData('80000000');

    const result = runScript(locking, unlocking);
    if (!result.success) console.log('be2num 0x80000000 ERROR:', result.error);
    expect(result.success).toBe(true);
  });

  it('add32: basic addition 1 + 2 = 3', () => {
    const reverseBytes4 =
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';
    const be2num = reverseBytes4 + pushData('00') + '7e' + '81';
    const num2be =
      '55' + '80' +  // OP_5 OP_NUM2BIN
      '54' + '7f' +  // OP_4 OP_SPLIT
      '75' +          // OP_DROP
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e'; // reverseBytes4

    // add32 = be2num + SWAP + be2num + ADD + push(2^32) + MOD + num2be
    const add32 = be2num + '7c' + be2num + '93' + pushData('0000000001') + '97' + num2be;

    // Push 0x00000001 and 0x00000002, add32 should give 0x00000003
    const unlocking = pushData('00000001') + pushData('00000002');
    const locking = add32 + pushData('00000003') + '87'; // OP_EQUAL
    const result = runScript(locking, unlocking);
    if (!result.success) console.log('add32 1+2 ERROR:', result.error);
    expect(result.success).toBe(true);
  });

  it('add32: overflow wraps (0xFFFFFFFF + 1 = 0)', () => {
    const reverseBytes4 =
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';
    const be2num = reverseBytes4 + pushData('00') + '7e' + '81';
    const num2be =
      '55' + '80' +  // OP_5 OP_NUM2BIN
      '54' + '7f' +  // OP_4 OP_SPLIT
      '75' +          // OP_DROP
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';

    const add32 = be2num + '7c' + be2num + '93' + pushData('0000000001') + '97' + num2be;

    // 0xFFFFFFFF + 0x00000001 = 0x100000000 mod 2^32 = 0x00000000
    const unlocking = pushData('ffffffff') + pushData('00000001');
    const locking = add32 + pushData('00000000') + '87'; // OP_EQUAL
    const result = runScript(locking, unlocking);
    if (!result.success) console.log('add32 overflow ERROR:', result.error);
    expect(result.success).toBe(true);
  });

  it('add32: large values (0x80000000 + 0x80000000)', () => {
    const reverseBytes4 =
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';
    const be2num = reverseBytes4 + pushData('00') + '7e' + '81';
    const num2be =
      '55' + '80' +
      '54' + '7f' +
      '75' +
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';

    const add32 = be2num + '7c' + be2num + '93' + pushData('0000000001') + '97' + num2be;

    // 0x80000000 + 0x80000000 = 0x100000000 mod 2^32 = 0
    const unlocking = pushData('80000000') + pushData('80000000');
    const locking = add32 + pushData('00000000') + '87';
    const result = runScript(locking, unlocking);
    if (!result.success) console.log('add32 large ERROR:', result.error);
    expect(result.success).toBe(true);
  });

  it('rotr: ROTR(2) on 0x6a09e667 (numeric approach)', () => {
    // New ROTR(2) using numeric DIV+MUL approach:
    // be2num, DUP, push(4), DIV, SWAP, push(2^30), MUL, push(2^32), MOD, ADD, num2be
    const reverseBytes4 =
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';
    const be2num = reverseBytes4 + pushData('00') + '7e' + '81';
    const num2be =
      '55' + '80' + '54' + '7f' + '75' +
      '51' + '7f' + '51' + '7f' + '51' + '7f' +
      '7c' + '7e' + '7c' + '7e' + '7c' + '7e';

    // ROTR(x, 2):
    // be2num(x), DUP, push(4=2^2), DIV, SWAP, push(2^30), MUL, push(2^32), MOD, ADD, num2be
    const rotr2 =
      be2num +
      '76' +                       // DUP
      '54' +                       // OP_4 (= 2^2)
      '96' +                       // OP_DIV
      '7c' +                       // SWAP
      pushData('00000040') +       // push 2^30 = 1073741824 (LE: 0x40000000)
      '95' +                       // OP_MUL
      pushData('0000000001') +     // push 2^32 = 4294967296
      '97' +                       // OP_MOD
      '93' +                       // OP_ADD
      num2be;

    // x = 0x6A09E667
    // x >> 2 = 0x1A827999
    // (x * 2^30) mod 2^32: x & 0x3 = 3, 3 * 2^30 = 0xC0000000
    // ROTR = 0x1A827999 + 0xC0000000 = 0xDA827999
    const expected = 'da827999';
    const unlocking = pushData('6a09e667');
    const locking = rotr2 + pushData(expected) + '87';
    const result = runScript(locking, unlocking);
    if (!result.success) console.log('rotr ERROR:', result.error);
    expect(result.success).toBe(true);
  });
});
