/**
 * Direct blake3 codegen output tests.
 * Tests setup, output extraction, and round correctness in isolation.
 */
import { describe, it, expect } from 'vitest';
import { generateCompressOps } from '../passes/blake3-codegen.js';
import { emitMethod } from '../passes/06-emit.js';

// Minimal script runner (no dependency on runar-testing ScriptVM)
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function pushHex(hex: string): string {
  const bytes = hexToBytes(hex);
  if (bytes.length <= 75) return bytes.length.toString(16).padStart(2, '0') + hex;
  if (bytes.length <= 255) return '4c' + bytes.length.toString(16).padStart(2, '0') + hex;
  const lo = (bytes.length & 0xff).toString(16).padStart(2, '0');
  const hi = ((bytes.length >> 8) & 0xff).toString(16).padStart(2, '0');
  return '4d' + lo + hi + hex;
}

// Import ScriptVM dynamically from the testing package
async function createVM() {
  const vmPath = '../../../runar-testing/src/vm/index.js';
  const mod = await import(vmPath);
  return new mod.ScriptVM({ maxOps: 10_000_000 }) as {
    executeHex(hex: string): {
      success: boolean;
      stack: Uint8Array[];
      error?: string;
    };
  };
}

function runCompress(vm: { executeHex(hex: string): { success: boolean; stack: Uint8Array[]; error?: string } },
  cvHex: string, blockHex: string, numRounds: number): { hash: string; error?: string } {
  const ops = generateCompressOps(numRounds);
  const result = emitMethod({ name: 'test', ops, maxStackDepth: 40 });
  const unlocking = pushHex(cvHex) + pushHex(blockHex);
  const vmResult = vm.executeHex(unlocking + result.scriptHex);
  if (vmResult.error) return { hash: '', error: vmResult.error };
  if (vmResult.stack.length !== 1 || vmResult.stack[0]!.length !== 32) {
    return {
      hash: '',
      error: `Expected 1x32B, got ${vmResult.stack.length} items: ${vmResult.stack.map(s => `(${s.length}B)${bytesToHex(s)}`).join(', ')}`,
    };
  }
  return { hash: bytesToHex(vmResult.stack[0]!) };
}

const BLAKE3_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const BLAKE3_IV_HEX = BLAKE3_IV.map(w => w.toString(16).padStart(8, '0')).join('');

const MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
function rotr32(x: number, n: number) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
function addU32(a: number, b: number) { return (a + b) >>> 0; }
function gFn(st: number[], a: number, b: number, c: number, d: number, mx: number, my: number) {
  st[a] = addU32(addU32(st[a]!, st[b]!), mx);
  st[d] = rotr32(st[d]! ^ st[a]!, 16);
  st[c] = addU32(st[c]!, st[d]!);
  st[b] = rotr32(st[b]! ^ st[c]!, 12);
  st[a] = addU32(addU32(st[a]!, st[b]!), my);
  st[d] = rotr32(st[d]! ^ st[a]!, 8);
  st[c] = addU32(st[c]!, st[d]!);
  st[b] = rotr32(st[b]! ^ st[c]!, 7);
}
function roundFn(st: number[], m: number[]) {
  gFn(st, 0, 4, 8, 12, m[0]!, m[1]!);
  gFn(st, 1, 5, 9, 13, m[2]!, m[3]!);
  gFn(st, 2, 6, 10, 14, m[4]!, m[5]!);
  gFn(st, 3, 7, 11, 15, m[6]!, m[7]!);
  gFn(st, 0, 5, 10, 15, m[8]!, m[9]!);
  gFn(st, 1, 6, 11, 12, m[10]!, m[11]!);
  gFn(st, 2, 7, 8, 13, m[12]!, m[13]!);
  gFn(st, 3, 4, 9, 14, m[14]!, m[15]!);
}
function permute(m: number[]) { return MSG_PERM.map(i => m[i]!); }

function referenceCompress(cvHex: string, blockHex: string, numRounds: number): string {
  const cv: number[] = [];
  for (let i = 0; i < 8; i++) cv.push(parseInt(cvHex.substring(i * 8, i * 8 + 8), 16));
  const m: number[] = [];
  for (let i = 0; i < 16; i++) m.push(parseInt(blockHex.substring(i * 8, i * 8 + 8), 16));
  const state = [
    ...cv,
    BLAKE3_IV[0]!, BLAKE3_IV[1]!, BLAKE3_IV[2]!, BLAKE3_IV[3]!,
    0, 0, 64, 11,
  ];
  let msg = [...m];
  for (let r = 0; r < numRounds; r++) {
    roundFn(state, msg);
    if (r < numRounds - 1) msg = permute(msg);
  }
  const output: number[] = [];
  for (let i = 0; i < 8; i++) output.push((state[i]! ^ state[i + 8]!) >>> 0);
  return output.map(w => w.toString(16).padStart(8, '0')).join('');
}

describe('blake3 codegen — isolated phase tests', () => {
  const block = '00'.repeat(64);
  let vm: Awaited<ReturnType<typeof createVM>>;

  it('setup VM', async () => {
    vm = await createVM();
    expect(vm).toBeDefined();
  });

  it('0 rounds — tests setup + output extraction only', () => {
    const result = runCompress(vm, BLAKE3_IV_HEX, block, 0);
    const expected = referenceCompress(BLAKE3_IV_HEX, block, 0);
    console.log('0 rounds actual:  ', result.hash || result.error);
    console.log('0 rounds expected:', expected);
    expect(result.error).toBeUndefined();
    expect(result.hash).toBe(expected);
  });

  it('1 round — tests first round of G calls', () => {
    const result = runCompress(vm, BLAKE3_IV_HEX, block, 1);
    const expected = referenceCompress(BLAKE3_IV_HEX, block, 1);
    console.log('1 round actual:  ', result.hash || result.error);
    console.log('1 round expected:', expected);
    expect(result.error).toBeUndefined();
    expect(result.hash).toBe(expected);
  });

  it('7 rounds — full compression', () => {
    const result = runCompress(vm, BLAKE3_IV_HEX, block, 7);
    const expected = referenceCompress(BLAKE3_IV_HEX, block, 7);
    console.log('7 rounds actual:  ', result.hash || result.error);
    console.log('7 rounds expected:', expected);
    expect(result.error).toBeUndefined();
    expect(result.hash).toBe(expected);
  });

  it('7 rounds — non-zero block data ("abc" padded)', () => {
    const abcBlock = '616263' + '00'.repeat(61);
    const result = runCompress(vm, BLAKE3_IV_HEX, abcBlock, 7);
    const expected = referenceCompress(BLAKE3_IV_HEX, abcBlock, 7);
    expect(result.error).toBeUndefined();
    expect(result.hash).toBe(expected);
  });

  it('7 rounds — non-IV chaining value', () => {
    const customCV = 'deadbeef'.repeat(8);
    const ffBlock = 'ff'.repeat(64);
    const result = runCompress(vm, customCV, ffBlock, 7);
    const expected = referenceCompress(customCV, ffBlock, 7);
    expect(result.error).toBeUndefined();
    expect(result.hash).toBe(expected);
  });
});
