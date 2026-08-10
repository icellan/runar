/**
 * I4 — per-span fidelity map. In milestone 1 every segment is an asm island
 * (byte-exact by construction), so all verdicts are 'asm-island'; recognized
 * spans carry their idiom name. The summary tiles the whole script.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { generalLift } from '../src/general-lift.js';
import { computeFidelity } from '../src/fidelity.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();
const bytes = hexToBytes(ftkHex);
const segments = generalLift(disassemble(bytes)).segments;

describe('computeFidelity', () => {
  const map = computeFidelity(bytes, segments);

  it('covers the whole script with asm-island verdicts in milestone 1', () => {
    expect(map.summary.totalBytes).toBe(1428);
    expect(map.summary.coveredBytes).toBe(1428);
    expect(map.summary.asmIslands).toBe(segments.length);
    expect(map.summary.byteVerified).toBe(0);
    expect(map.spans.every((s) => s.verdict === 'asm-island')).toBe(true);
  });

  it('surfaces recognized idiom names on their spans', () => {
    const idioms = map.spans.map((s) => s.idiom).filter(Boolean);
    expect(idioms).toContain('p2pkh_sig_gate');
    expect(idioms).toContain('op_push_tx');
    expect(idioms).toContain('op_return_state');
  });
});
