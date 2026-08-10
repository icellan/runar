/**
 * S9 — native-if structured reconstruction. Control flow is lifted to real
 * Rúnar `if (cond) { ... } else { ... }` with the branch bodies kept as
 * byte-exact asm() islands ("the asm in between"); large top-level branches are
 * recovered as named private methods (function boundaries). The owner gate is
 * still lifted to real asserts. This view is semantic-only (conditions are
 * reconstructed) — the byte-exact image is the companion asm tiling.
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

describe('renderStructured (S9)', () => {
  it('lifts the owner gate to real Rúnar with the pkh via the constructor', () => {
    expect(src).toContain('extends UnsafeSmartContract');
    expect(src).toContain('assert(hash160(pubKey) === this.ownerPkh)');
    expect(src).toContain('assert(checkSig(sig, pubKey))');
    expect(src).toContain('constructor(ownerPkh: ByteString)');
  });

  it('emits native if/else with asm() branch bodies ("asm in between")', () => {
    // structural keywords present
    expect(src).toMatch(/\n {4,}if \(/);
    expect(src).toContain('} else {');
    // branch bodies are opcode arrays, not hex blobs. (The OP_PUSH_TX internals —
    // incl. its low-S OP_SUB/OP_NIP + DER-length OP_1SUB ifs — are now collapsed
    // into assert(checkPreimage(preimage)); see op-push-tx-spirit.test.ts. These
    // are the output-building branches that remain.)
    expect(src).toContain('body: [OP_NIP]');
    // varint-size select: OP_4 / OP_2
    expect(src).toContain('body: [OP_4]');
    expect(src).toContain('body: [OP_2]');
  });

  it('renders an OP_NOTIF as a negated condition', () => {
    expect(src).toMatch(/if \(!/);
  });

  it('recovers the 436-op top-level branch as a named private method', () => {
    expect(src).toMatch(/private \w+\(\): void \{/);
    expect(src).toMatch(/this\.\w+\(\);/);
    expect(src).toContain('function boundary');
  });

  it('inlines the ACTUAL condition ops (no fabricated names), e.g. OP_GREATERTHAN', () => {
    // the value the IF tests is the real script — shown inline, ending in the
    // comparison op — not an undefined `cond0`
    expect(src).toMatch(/if \(asm\(\[[^\]]*OP_GREATERTHAN\]\)\)/);
    expect(src).not.toMatch(/\bcond\d+\b/);
    // best-effort symbolic annotation (≈) accompanies recovered conditions
    expect(src).toMatch(/≈/);
  });

  it('breaks remaining comparison conditions into recovered left/right operands', () => {
    // condComment still splits an asm-form compare into its two operands. (The
    // low-S compare itself is now the lifted spirit block — see
    // low-s-spirit.test.ts; this covers the conditions that stay asm.)
    expect(src).toContain('left  ≈');
    expect(src).toContain('right ≈');
  });

  it('collapses the OP_PUSH_TX construction (incl. its byte-reversal) to checkPreimage', () => {
    // the byte-reversal shuffle lives inside the optimal OP_PUSH_TX idiom, which is
    // now an atomic assert(checkPreimage(preimage)) — see op-push-tx-spirit.test.ts.
    // (The symbolic reverse(...) recognition itself is unit-tested in symcore S2.)
    expect(src).toContain('assert(checkPreimage(preimage));');
    expect(src).not.toContain('OP_16, OP_SPLIT, OP_15, OP_SPLIT');
  });

  it('marks the view semantic-only and points at the byte-exact companion', () => {
    expect(src.toLowerCase()).toContain('semantic');
    expect(src).toMatch(/byte-exact|byte-identical|fidelity/i);
  });

  it('describes itself as a reconstruction without injecting a byte-identity verdict', () => {
    // renderStructured states facts; the VERIFIED/WARNING verdict is added by
    // the caller after a real compile-and-compare (decompileViaSemantic).
    expect(src).toMatch(/reconstruction/i);
    expect(src.toLowerCase()).toContain('recovered');
    expect(src).not.toContain('VERIFIED');
    expect(src).not.toContain('WARNING');
  });

  it('renders asm() island bodies as opcode arrays, not hex blobs', () => {
    const arrays = [...src.matchAll(/body: \[([^\]]*)\]/g)].map((m) => m[1]!);
    expect(arrays.length).toBeGreaterThan(5);
    // every token is an OP_* opcode or a push('<hex>') (optionally annotated
    // with an inline ASCII comment) — never a bare hex blob
    for (const a of arrays) {
      const toks = a
        .replace(/\/\*.*?\*\//g, '')
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      for (const t of toks) {
        expect(t).toMatch(/^(OP_[A-Z0-9_]+|push\('[0-9a-f]*'\))$/);
      }
    }
    // no asm body should be a raw hex string anymore
    expect(src).not.toMatch(/body: '[0-9a-f]/);
  });

  it('imports the opcode identifiers it references', () => {
    expect(src).toMatch(/import \{[^}]*\bOP_SUB\b[^}]*\} from 'runar-lang'/);
  });
});
