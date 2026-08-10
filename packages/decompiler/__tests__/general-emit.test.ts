/**
 * I4 — contract recovery + annotated source emission.
 *
 * recoverContract derives the contract skeleton (stateful/stateless, owner
 * pkh, OP_RETURN state fields) from the labeled segments. renderSemanticSource
 * emits annotated Rúnar source whose executable body is byte-exact asm()
 * islands — so for milestone 1 it recompiles byte-identical (Invariant 2 is
 * even stronger than required).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { generalLift } from '../src/general-lift.js';
import { recoverContract, renderSemanticSource, buildCandidateProgram } from '../src/general-emit.js';
import { verifyDecompilationAnf } from '../src/verify.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();
const bytes = hexToBytes(ftkHex);
const segments = generalLift(disassemble(bytes)).segments;

describe('recoverContract', () => {
  const recovered = recoverContract(bytes, segments);

  it('detects stateful (OP_PUSH_TX present)', () => {
    expect(recovered.kind).toBe('stateful');
  });

  it('recovers the owner pubkey hash', () => {
    expect(recovered.ownerPkh).toBe('062962b603bd7fd0dc4b35d12bbac0850f8eb4c8');
  });

  it('recovers OP_RETURN state fields with ascii decode', () => {
    expect(recovered.state.map((s) => s.hex)).toEqual([
      '783eadfd045de5484fc4b81ab875df3d96380251',
      '00',
      '46544b',
      '64656d6f',
    ]);
    expect(recovered.state[2]!.ascii).toBe('FTK');
    expect(recovered.state[3]!.ascii).toBe('demo');
  });
});

describe('renderSemanticSource', () => {
  const recovered = recoverContract(bytes, segments);
  const src = renderSemanticSource(recovered, bytes);

  it('annotates recognized idiom regions and uses the asm-capable base class', () => {
    expect(src).toContain('op_push_tx');
    expect(src).toContain('p2pkh_sig_gate');
    expect(src).toContain('op_return_state');
    expect(src).toContain('FTK');
    expect(src).toContain('extends UnsafeSmartContract');
  });

  it('candidate ANF recompiles byte-identical (Invariant 2)', () => {
    const v = verifyDecompilationAnf(bytes, buildCandidateProgram(recovered, bytes));
    expect(v.ok).toBe(true);
  });
});
