/**
 * S8 — compiling reconstruction. The leading P2PKH gate is lifted to real
 * Rúnar with the owner pkh parameterized via the constructor; the remainder is
 * a multi-block set of annotated asm islands. The source compiles to a
 * template; splicing the recovered constructor arg reproduces the input
 * byte-identical.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { generalLift } from '../src/general-lift.js';
import { recoverContract, renderCompiling } from '../src/general-emit.js';
import { verifyCompiling } from '../src/verify.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();
const bytes = hexToBytes(ftkHex);
const segments = generalLift(disassemble(bytes)).segments;
const recovered = recoverContract(bytes, segments);
const src = renderCompiling(recovered, bytes);

describe('renderCompiling', () => {
  it('lifts the owner gate and passes the pkh through the constructor', () => {
    expect(src).toContain('assert(hash160(pubKey) === this.ownerPkh)');
    expect(src).toContain('assert(checkSig(sig, pubKey))');
    expect(src).toContain('readonly ownerPkh: ByteString;');
    expect(src).toContain('constructor(ownerPkh: ByteString) { super(ownerPkh); this.ownerPkh = ownerPkh; }');
    // recovered deploy arg reported, not hardcoded as a literal
    expect(src).toContain('ownerPkh = 0x062962b603bd7fd0dc4b35d12bbac0850f8eb4c8');
    expect(src).not.toContain("ownerPkh: ByteString = '062962");
  });

  it('keeps the multi-block annotated structure with Rúnar-equivalents', () => {
    const blocks = (src.match(/asm\(\{/g) ?? []).length;
    expect(blocks).toBeGreaterThanOrEqual(10);
    expect(src).toContain('[asm:op_push_tx]');
    expect(src).toContain('[asm:op_return_state]');
    expect(src).toContain('unrolled');
    // recognized blocks now carry their Rúnar meaning (restored detail)
    expect(src).toContain('assert(checkPreimage(preimage))');
    expect(src).toContain('extractOutputs(preimage)');
  });

  it('declares the recovered preimage input on the method (deepest, stack order)', () => {
    expect(src).toContain('public spend(preimage: SigHashPreimage, sig: Sig, pubKey: PubKey): void');
    expect(src).toContain('SigHashPreimage');
  });

  it('lifts the OP_RETURN state to the opReturn shorthand', () => {
    expect(src).toContain('opReturn([');
    expect(src).toContain("'46544b' /* \"FTK\" */");
    expect(src).toContain("'64656d6f' /* \"demo\" */");
  });

  it('separates the asm blocks with blank lines', () => {
    expect(src).toMatch(/\}\);\n\n {4}\/\/ \[asm:/);
  });

  it('template + recovered constructor arg recompiles byte-identical', () => {
    const v = verifyCompiling(bytes, src, { 0: recovered.ownerPkh! });
    expect(v.ok).toBe(true);
  });
});
