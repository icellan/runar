/**
 * Per-span fidelity map.
 *
 * Each segment gets a verdict describing how trustworthy its recovery is:
 *   - `asm-island`    — verbatim bytes, byte-exact by construction (the bytes
 *                       were never transformed). Carries the idiom name when
 *                       the span was recognized.
 *   - `byte-verified` — a lifted span that re-emits to exactly its original
 *                       bytes (computed by per-span recompile; reserved for
 *                       later milestones once truly lifted segments exist).
 *   - `semantic-only` — a lifted span that recompiles but whose bytes differ.
 *
 * Milestone 1 produces only asm islands, so every verdict is `asm-island`.
 */

import type { Segment } from './general-lift.js';

export type FidelityVerdict = 'asm-island' | 'byte-verified' | 'semantic-only';

export interface FidelitySpan {
  originalRange: [number, number];
  verdict: FidelityVerdict;
  idiom?: string;
  note?: string;
}

export interface FidelitySummary {
  byteVerified: number;
  semanticOnly: number;
  asmIslands: number;
  coveredBytes: number;
  totalBytes: number;
}

export interface FidelityMap {
  spans: FidelitySpan[];
  summary: FidelitySummary;
}

export function computeFidelity(bytes: Uint8Array, segments: Segment[]): FidelityMap {
  const spans: FidelitySpan[] = segments.map((seg) => {
    if (seg.kind === 'asm') {
      const span: FidelitySpan = { originalRange: seg.span, verdict: 'asm-island' };
      if (seg.idiom) span.idiom = seg.idiom;
      if (seg.analysis) span.note = seg.analysis;
      return span;
    }
    // Truly lifted segments arrive in a later milestone; until then there are
    // none, so this branch is intentionally minimal.
    return { originalRange: seg.span, verdict: 'semantic-only' };
  });

  const count = (v: FidelityVerdict) => spans.filter((s) => s.verdict === v).length;
  const coveredBytes = spans.reduce((n, s) => n + (s.originalRange[1] - s.originalRange[0]), 0);

  return {
    spans,
    summary: {
      byteVerified: count('byte-verified'),
      semanticOnly: count('semantic-only'),
      asmIslands: count('asm-island'),
      coveredBytes,
      totalBytes: bytes.length,
    },
  };
}
