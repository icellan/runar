/**
 * Reference SHA-256 compression to validate codegen correctness.
 * Computes intermediate values and tests specific sub-computations.
 */
import { describe, it, expect } from 'vitest';

// --- Reference SHA-256 implementation ---

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}
function shr(x: number, n: number): number {
  return x >>> n;
}
function ch(e: number, f: number, g: number): number {
  return ((e & f) ^ (~e & g)) >>> 0;
}
function maj(a: number, b: number, c: number): number {
  return ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
}
function bigSigma0(a: number): number {
  return (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
}
function bigSigma1(e: number): number {
  return (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
}
function smallSigma0(x: number): number {
  return (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)) >>> 0;
}
function smallSigma1(x: number): number {
  return (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)) >>> 0;
}
function add32(a: number, b: number): number {
  return (a + b) >>> 0;
}

function sha256compress(stateHex: string, blockHex: string): string {
  // Parse state into 8 words
  const H: number[] = [];
  for (let i = 0; i < 8; i++) {
    H.push(parseInt(stateHex.substring(i * 8, i * 8 + 8), 16));
  }

  // Parse block into 16 words
  const W: number[] = [];
  for (let i = 0; i < 16; i++) {
    W.push(parseInt(blockHex.substring(i * 8, i * 8 + 8), 16));
  }

  // W expansion
  for (let t = 16; t < 64; t++) {
    W.push(add32(add32(add32(
      smallSigma1(W[t - 2]!),
      W[t - 7]!),
      smallSigma0(W[t - 15]!)),
      W[t - 16]!));
  }

  // Initialize working variables
  let [a, b, c, d, e, f, g, h] = H;

  // 64 rounds
  for (let t = 0; t < 64; t++) {
    const T1 = add32(add32(add32(add32(h!, bigSigma1(e!)), ch(e!, f!, g!)), K[t]!), W[t]!);
    const T2 = add32(bigSigma0(a!), maj(a!, b!, c!));
    h = g!; g = f!; f = e!; e = add32(d!, T1);
    d = c!; c = b!; b = a!; a = add32(T1, T2);
  }

  // Add initial state
  const result = [
    add32(a!, H[0]!), add32(b!, H[1]!), add32(c!, H[2]!), add32(d!, H[3]!),
    add32(e!, H[4]!), add32(f!, H[5]!), add32(g!, H[6]!), add32(h!, H[7]!),
  ];

  return result.map(w => w.toString(16).padStart(8, '0')).join('');
}

describe('sha256 reference', () => {
  it('reference implementation produces correct SHA-256("abc")', () => {
    const init = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
    const block =
      '6162638000000000000000000000000000000000000000000000000000000000' +
      '0000000000000000000000000000000000000000000000000000000000000018';
    const result = sha256compress(init, block);
    expect(result).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('prints W expansion and round values for debugging', () => {
    const init = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
    const block =
      '6162638000000000000000000000000000000000000000000000000000000000' +
      '0000000000000000000000000000000000000000000000000000000000000018';

    // Parse
    const H: number[] = [];
    for (let i = 0; i < 8; i++) H.push(parseInt(init.substring(i * 8, i * 8 + 8), 16));
    const W: number[] = [];
    for (let i = 0; i < 16; i++) W.push(parseInt(block.substring(i * 8, i * 8 + 8), 16));

    // W expansion
    for (let t = 16; t < 64; t++) {
      W.push(add32(add32(add32(smallSigma1(W[t-2]!), W[t-7]!), smallSigma0(W[t-15]!)), W[t-16]!));
    }

    console.log('First 20 W values:');
    for (let i = 0; i < 20; i++) {
      console.log(`  W[${i}] = 0x${W[i]!.toString(16).padStart(8, '0')}`);
    }

    // Check codegen round order. In the codegen, the round function uses:
    // Stack: [W0..W63, a, b, c, d, e, f, g, h] (a=TOS)
    // Registers: a=TOS, h=depth 7
    // The codegen does register rotation like this:
    //   new_a = T1 + T2
    //   new_e = d + T1
    //   drop old h
    //   roll to reorder
    // This matches the standard: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2

    let [a, b, c, d, e, f, g, h] = H;
    console.log('\nRound 0 input:');
    console.log(`  a=0x${a!.toString(16).padStart(8, '0')} b=0x${b!.toString(16).padStart(8, '0')} c=0x${c!.toString(16).padStart(8, '0')} d=0x${d!.toString(16).padStart(8, '0')}`);
    console.log(`  e=0x${e!.toString(16).padStart(8, '0')} f=0x${f!.toString(16).padStart(8, '0')} g=0x${g!.toString(16).padStart(8, '0')} h=0x${h!.toString(16).padStart(8, '0')}`);

    const T1 = add32(add32(add32(add32(h!, bigSigma1(e!)), ch(e!, f!, g!)), K[0]!), W[0]!);
    const T2 = add32(bigSigma0(a!), maj(a!, b!, c!));
    console.log(`  T1=0x${T1.toString(16).padStart(8, '0')} T2=0x${T2.toString(16).padStart(8, '0')}`);
    console.log(`  new_a=0x${add32(T1, T2).toString(16).padStart(8, '0')} new_e=0x${add32(d!, T1).toString(16).padStart(8, '0')}`);
  });
});
