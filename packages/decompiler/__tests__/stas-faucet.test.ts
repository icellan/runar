/**
 * S10 — real on-chain STAS token genesis/metadata output (tx 48baadcb…): a
 * P2PKH owner gate + OP_RETURN carrying the token-metadata JSON. No OP_PUSH_TX /
 * preimage, so the structured view has no reconstructed conditions and recompiles
 * BYTE-IDENTICAL — the decompiler's checked verdict is VERIFIED, not a warning.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { decompile } from '../src/index.js';
import { verifyCompiling } from '../src/verify.js';

const hex = readFileSync(new URL('./fixtures/stas-faucet.hex', import.meta.url), 'utf8').trim();
const bytes = hexToBytes(hex);
const ownerPkh = '783eadfd045de5484fc4b81ab875df3d96380251';

describe('STAS faucet metadata output (S10)', () => {
  const res = decompile(bytes, { semantic: true });

  it('lifts the owner gate and the OP_RETURN token metadata', () => {
    expect(res.recoveryPath).toBe('semantic');
    expect(res.source).toContain('assert(hash160(pubKey) === this.ownerPkh)');
    expect(res.source).toContain('assert(checkSig(sig, pubKey))');
    expect(res.source).toContain('[op_return_state]');
    expect(res.source).toContain('opReturn([');
    expect(res.source).toContain('"symbol":"FTK"');
    expect(res.source).toContain('"protocolId":"STAS"');
    expect(res.source).toContain(`new _Recovered(ownerPkh = 0x${ownerPkh})`);
  });

  it('has no preimage/control-flow (pure metadata output)', () => {
    expect(res.source).not.toContain('SigHashPreimage');
    expect(res.source).not.toMatch(/\n {4,}if \(/);
  });

  it('the structured view itself recompiles BYTE-IDENTICAL (verdict = VERIFIED)', () => {
    expect(res.sourceByteIdentical).toBe(true);
    expect(res.source).toContain('✓ VERIFIED');
    expect(res.source).not.toContain('⚠ WARNING');
    const v = verifyCompiling(bytes, res.source, { 0: ownerPkh });
    expect(v.ok).toBe(true);
  });

  it('the byte-exact companion also round-trips', () => {
    expect(res.ok).toBe(true);
    const v = verifyCompiling(bytes, res.byteExactSource!, { 0: ownerPkh });
    expect(v.ok).toBe(true);
  });
});
