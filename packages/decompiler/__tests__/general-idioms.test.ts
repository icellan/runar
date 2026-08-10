/**
 * Idiom matchers for the general lifter (milestone 1: OP_PUSH_TX / FT family).
 *
 * Each matcher is a pure function over the op stream. Tests feed real op
 * slices from the FTK/demo fixture and assert the recovered span + data.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes, bytesToHex } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import {
  opReturnState,
  p2pkhSigGate,
  opPushTx,
  preimageExtract,
  outputsEnforce,
  buildP2pkhOutput,
} from '../src/general-idioms.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();
const ops = disassemble(hexToBytes(ftkHex));

describe('op_return_state idiom', () => {
  it('recovers the trailing OP_RETURN push fields to end of script', () => {
    const i = ops.findIndex((o) => o.name === 'OP_RETURN');
    const m = opReturnState.match(ops, i);
    expect(m).not.toBeNull();
    expect(m!.name).toBe('op_return_state');
    expect(m!.startIndex).toBe(i);
    expect(m!.endIndex).toBe(ops.length);
    expect(m!.data!.fields).toEqual([
      '783eadfd045de5484fc4b81ab875df3d96380251',
      '00',
      '46544b', // "FTK"
      '64656d6f', // "demo"
    ]);
  });

  it('does not match when op is not OP_RETURN', () => {
    expect(opReturnState.match(ops, 0)).toBeNull();
  });
});

describe('p2pkh_sig_gate idiom', () => {
  it('recovers the leading owner pubkey-hash gate', () => {
    const m = p2pkhSigGate.match(ops, 0);
    expect(m).not.toBeNull();
    expect(m!.name).toBe('p2pkh_sig_gate');
    expect(m!.startIndex).toBe(0);
    expect(m!.data!.pubKeyHash).toBe('062962b603bd7fd0dc4b35d12bbac0850f8eb4c8');
    // span covers DUP HASH160 <20> EQUALVERIFY CHECKSIG VERIFY = 6 ops
    expect(m!.endIndex).toBe(6);
  });
});

describe('op_push_tx idiom', () => {
  it('recognizes the optimal OP_PUSH_TX construction via its canonical constants', () => {
    // starts at the preimage DUP/HASH256 (op index 6, right after the sig gate)
    const m = opPushTx.match(ops, 6);
    expect(m).not.toBeNull();
    expect(m!.name).toBe('op_push_tx');
    expect(m!.startIndex).toBe(6);
    // ends just past the CHECKSIGVERIFY following the pushtx pubkey
    const end = m!.endIndex;
    expect(ops[end - 1]!.name).toBe('OP_CHECKSIGVERIFY');
  });
});

describe('preimage_extract idiom', () => {
  it('recognizes the BIP-143 field-carving prologue (offset 525)', () => {
    const i = ops.findIndex((o) => o.offset === 525);
    const m = preimageExtract.match(ops, i);
    expect(m).not.toBeNull();
    expect(m!.name).toBe('preimage_extract');
    expect(m!.endIndex).toBe(i + 10);
    expect(ops[m!.endIndex - 1]!.name).toBe('OP_SPLIT');
  });

  it('does not match a non-prologue position', () => {
    expect(preimageExtract.match(ops, 0)).toBeNull();
  });
});

describe('outputs_enforce idiom', () => {
  it('recognizes the final HASH256==hashOutputs + cleanup before OP_RETURN', () => {
    const i = ops.findIndex((o) => o.offset === 1389);
    const m = outputsEnforce.match(ops, i);
    expect(m).not.toBeNull();
    expect(m!.name).toBe('outputs_enforce');
    expect(m!.endIndex).toBe(i + 6);
    expect(ops[m!.endIndex]!.name).toBe('OP_RETURN');
  });

  it('does not match a HASH256/EQUAL not followed by the cleanup+OP_RETURN tail', () => {
    const firstHash = ops.findIndex((o) => o.name === 'OP_HASH256');
    expect(outputsEnforce.match(ops, firstHash)).toBeNull();
  });
});

describe('build_p2pkh_output idiom', () => {
  it('recognizes a P2PKH script-template push (1976a914)', () => {
    const i = ops.findIndex((o) => o.data && bytesToHex(o.data) === '1976a914');
    expect(i).toBeGreaterThan(0);
    const m = buildP2pkhOutput.match(ops, i);
    expect(m).not.toBeNull();
    expect(m!.name).toBe('build_p2pkh_output');
    expect(m!.endIndex).toBe(i + 1);
    expect(m!.data!.template).toBe('1976a914');
  });

  it('recognizes the 3-byte P2PKH prefix push (76a914)', () => {
    const i = ops.findIndex((o) => o.data && bytesToHex(o.data) === '76a914');
    expect(i).toBeGreaterThan(0);
    expect(buildP2pkhOutput.match(ops, i)!.data!.template).toBe('76a914');
  });
});
