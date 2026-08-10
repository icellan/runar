/**
 * S11 — "spirit" reconstruction lifts the MEANING, not the mechanism. The whole
 * optimal OP_PUSH_TX construction (sighash byte-reversal + low-S scalar + fixed
 * `r` + DER assembly with its length-handling ifs + final checkSig) is one idiom
 * whose purpose is `checkPreimage(preimage)`. The structured view collapses that
 * entire span to a single `assert(checkPreimage(preimage));` — exactly what the
 * byte-exact companion annotates — instead of exposing the internal arithmetic /
 * DER `if`s as fragments. Native-if reconstruction is reserved for the genuinely
 * unrecognized regions (the output-building logic), where the control flow IS the
 * contract's meaning.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { generalLift } from '../src/general-lift.js';
import { recoverContract, renderStructured } from '../src/general-emit.js';

const ftkHex = readFileSync(new URL('./fixtures/ftk-demo.hex', import.meta.url), 'utf8').trim();
const bytes = hexToBytes(ftkHex);
const segments = generalLift(disassemble(bytes)).segments;
const recovered = recoverContract(bytes, segments);
const src = renderStructured(recovered, bytes);

describe('optimal OP_PUSH_TX spirit reconstruction (S11)', () => {
  it('collapses the whole OP_PUSH_TX construction to assert(checkPreimage(preimage))', () => {
    expect(src).toContain('assert(checkPreimage(preimage));');
    expect(src).toMatch(/import \{[^}]*\bcheckPreimage\b[^}]*\} from 'runar-lang'/);
  });

  it('does NOT expose the mechanism (low-S scalar / byte-reversal) as fragments', () => {
    // the earlier wrong layer: the low-S arithmetic must not appear
    expect(src).not.toContain('reverseBytes(hash256(preimage))');
    expect(src).not.toContain('EC_N');
    expect(src).not.toContain('bin2num(sighash');
    expect(src).not.toContain('? EC_N - s : s');
    // ...nor the giant raw split/cat shuffle, nor the DER-length internals
    expect(src).not.toContain('OP_16, OP_SPLIT, OP_15, OP_SPLIT');
    expect(src).not.toMatch(/if \(asm\(\[[^\]]*OP_GREATERTHAN[^\]]*push\('414136d0/);
  });

  it('keeps the owner gate as real asserts right before the OP_PUSH_TX check', () => {
    expect(src).toContain('assert(hash160(pubKey) === this.ownerPkh)');
    const gateAt = src.indexOf('assert(checkSig(sig, pubKey))');
    const pushTxAt = src.indexOf('assert(checkPreimage(preimage))');
    expect(gateAt).toBeGreaterThan(-1);
    expect(pushTxAt).toBeGreaterThan(gateAt);
  });

  it('still reconstructs native if/else in the unrecognized (output-building) regions', () => {
    // confining idioms to atomic units must NOT lose the native-if view where the
    // control flow is the real logic
    expect(src).toMatch(/\n {4,}if \(/);
    expect(src).toContain('} else {');
    expect(src).toMatch(/private \w+\(\): void \{/); // function boundary still recovered
  });

  it('still flags the view as a non-byte-exact reconstruction', () => {
    expect(src.toLowerCase()).toContain('reconstruction');
    expect(src).toMatch(/byte-exact|byte-identical|companion|fidelity/i);
  });
});
