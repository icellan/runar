/**
 * S7 — readable reconstruction. Recognized idioms render as real Rúnar
 * (checkSig / hash160 / checkPreimage / extract* / outputs check / state
 * props); unrecognized regions are bracketed with their symbolic analysis.
 * Illustrative view — the byte-exact artifact remains the ANF/asm form.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { generalLift } from '../src/general-lift.js';
import { recoverContract, renderReadable } from '../src/general-emit.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();
const bytes = hexToBytes(ftkHex);
const segments = generalLift(disassemble(bytes)).segments;
const src = renderReadable(recoverContract(bytes, segments), bytes);

describe('renderReadable', () => {
  it('lifts the P2PKH owner gate to real Rúnar', () => {
    expect(src).toContain('hash160(pubKey)');
    expect(src).toContain('checkSig(sig, pubKey)');
    expect(src).toContain('062962b603bd7fd0dc4b35d12bbac0850f8eb4c8');
  });

  it('lifts OP_PUSH_TX and preimage extraction', () => {
    expect(src).toContain('checkPreimage(preimage)');
    expect(src).toContain('extractScriptCode(preimage)');
  });

  it('lifts the outputs-hash enforcement', () => {
    expect(src).toContain('extractOutputs(preimage)');
  });

  it('recovers OP_RETURN state as readonly properties', () => {
    expect(src).toContain('"FTK"');
    expect(src).toContain('"demo"');
    expect(src).toMatch(/readonly\s+\w+/);
  });

  it('brackets the unrecognized region with its symbolic analysis', () => {
    expect(src.toLowerCase()).toContain('unrolled');
    expect(src).toContain('8-byte amount');
  });

  it('declares the inferred spending inputs on the method', () => {
    expect(src).toMatch(/spend\(.*sig.*pubKey.*preimage.*\)/);
  });
});
