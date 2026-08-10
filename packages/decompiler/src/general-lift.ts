/**
 * General (semantic) lifter — milestone 1.
 *
 * Lifts a foreign Bitcoin Script byte stream into a list of `Segment`s, each
 * tagged with the original byte span it came from. Segments are either
 * structurally `lifted` (recovered Rúnar constructs — added in later
 * increments) or opaque `asm` islands (verbatim bytes the lifter can't model).
 *
 * The decomposition is anchored by Invariant 1 (tiling): rendering every
 * segment as a `raw_script` island of its ORIGINAL bytes must recompile
 * byte-identical to the input. `buildShadowProgram` produces that shadow
 * program; the foundation lifter below emits a single all-covering asm island
 * (equivalent to today's raw_script floor), which later increments split apart.
 */

import type { ANFProgram } from 'runar-compiler';
import { bytesToHex } from 'runar-testing';
import type { Op } from './types.js';
import { matchIdiomAt } from './general-idioms.js';
import { analyzeRegion } from './symanalyze.js';

/** A span of the original script lifted to a (future) Rúnar construct. */
export interface LiftedSegment {
  kind: 'lifted';
  span: [number, number];
}

/** A span of the original script kept verbatim as an opaque asm island. */
export interface AsmSegment {
  kind: 'asm';
  span: [number, number];
  /** Stack elements the island consumes. */
  inArity: number;
  /** Stack elements the island produces. */
  outArity: number;
  /** Recognized idiom name, when the span matched the idiom registry. */
  idiom?: string;
  /** Idiom-recovered data (state fields, pubkey hash, …). */
  data?: Record<string, unknown>;
  /** Symbolic-analysis summary for an unrecognized span (recovered meaning). */
  analysis?: string;
}

export type Segment = LiftedSegment | AsmSegment;

export interface GeneralLiftResult {
  segments: Segment[];
}

export interface SegmentOptions {
  /**
   * Number of method parameters (= initial stack depth when the locking
   * script runs). The first island declares this as its `in_arity`; all
   * later islands declare `in_arity` 1. Because `raw_bytes` emits its bytes
   * verbatim regardless of arity, this chain is pure stack-depth bookkeeping
   * that keeps `compileFromANF` from underflowing — byte-identity is
   * unaffected.
   */
  paramCount?: number;
}

/**
 * Split an op stream into contiguous asm islands at the given op-index
 * boundaries (a boundary `b` starts a new island at `ops[b]`). Arities chain
 * as `{paramCount→1}` then `{1→1}…`, which never underflows and ends at depth
 * 1. Spans are byte offsets taken from the ops, so the islands tile the script
 * exactly.
 */
export function segmentByBoundaries(
  ops: Op[],
  boundaries: number[],
  opts: SegmentOptions = {},
): Segment[] {
  if (ops.length === 0) return [];
  const paramCount = opts.paramCount ?? 0;
  const cuts = [...new Set(boundaries)]
    .filter((b) => b > 0 && b < ops.length)
    .sort((a, b) => a - b);
  const starts = [0, ...cuts];
  const segments: AsmSegment[] = [];
  for (let i = 0; i < starts.length; i++) {
    const startIdx = starts[i]!;
    const endIdx = i + 1 < starts.length ? starts[i + 1]! : ops.length;
    const startOff = ops[startIdx]!.offset;
    const lastOp = ops[endIdx - 1]!;
    const endOff = lastOp.offset + lastOp.size;
    segments.push({
      kind: 'asm',
      span: [startOff, endOff],
      inArity: i === 0 ? paramCount : 1,
      outArity: 1,
    });
  }
  return segments;
}

/**
 * Idiom-driven lifter: scan the op stream left→right, emitting a labeled
 * segment for each recognized idiom span and an unlabeled asm island for each
 * gap between them. Every byte ends up in exactly one segment (tiling), and
 * arities chain via {paramCount→1}, {1→1}… so the shadow/candidate compiles.
 *
 * In milestone 1 all segments are asm islands; recognized ones carry an
 * `idiom` label + recovered `data`. Later increments promote some to truly
 * lifted Rúnar constructs.
 */
/** An op-index span from the idiom scan: a labeled idiom match or an unlabeled gap. */
export interface IdiomSpan {
  startIndex: number;
  endIndex: number;
  idiom?: string;
  data?: Record<string, unknown>;
}

/**
 * Scan a control-flow-free op range `[start, end)` left→right into idiom spans:
 * a labeled span for each recognized idiom and an unlabeled gap span for the
 * bytes between them. Matches that would straddle past `end` are skipped, so
 * callers can scan a single linear run in isolation. Shared by `generalLift`
 * (whole script) and the native-if renderer (per linear run).
 */
export function scanIdioms(ops: Op[], start: number, end: number): IdiomSpan[] {
  const spans: IdiomSpan[] = [];
  let gapStart = start;
  let i = start;
  const flushGap = (until: number) => {
    if (until > gapStart) spans.push({ startIndex: gapStart, endIndex: until });
  };
  while (i < end) {
    const m = matchIdiomAt(ops, i);
    if (m && m.endIndex > i && m.endIndex <= end) {
      flushGap(i);
      spans.push({ startIndex: m.startIndex, endIndex: m.endIndex, idiom: m.name, data: m.data });
      i = m.endIndex;
      gapStart = i;
    } else {
      i++;
    }
  }
  flushGap(end);
  return spans;
}

export function generalLift(ops: Op[], opts: SegmentOptions = {}): GeneralLiftResult {
  if (ops.length === 0) return { segments: [] };
  const paramCount = opts.paramCount ?? 0;

  // Phase 1 — idiom scan into op-index spans (labeled matches + raw gaps).
  const spans = scanIdioms(ops, 0, ops.length);

  // Phase 2 — spans → asm segments with byte offsets + chained arities.
  const segments: Segment[] = spans.map((sp, idx) => {
    const startOff = ops[sp.startIndex]!.offset;
    const lastOp = ops[sp.endIndex - 1]!;
    const endOff = lastOp.offset + lastOp.size;
    const seg: AsmSegment = {
      kind: 'asm',
      span: [startOff, endOff],
      inArity: idx === 0 ? paramCount : 1,
      outArity: 1,
    };
    if (sp.idiom) {
      seg.idiom = sp.idiom;
      if (sp.data) seg.data = sp.data;
    } else {
      // Unrecognized gap — recover meaning symbolically (bytes unchanged).
      const analysis = analyzeRegion(ops, sp.startIndex, sp.endIndex);
      if (analysis.findings.length > 0) seg.analysis = analysis.summary;
    }
    return seg;
  });
  return { segments };
}

/**
 * Render the segment list as a *shadow* ANFProgram: every segment becomes a
 * `raw_script` binding carrying its ORIGINAL bytes. Recompiling this must be
 * byte-identical to the input (Invariant 1) — it validates segmentation and
 * island arities independent of lift quality.
 */
export function buildShadowProgram(bytes: Uint8Array, segments: Segment[]): ANFProgram {
  const body = segments.map((seg, i) => {
    const slice = bytes.slice(seg.span[0], seg.span[1]);
    const inArity = seg.kind === 'asm' ? seg.inArity : 0;
    const outArity = seg.kind === 'asm' ? seg.outArity : 1;
    return {
      name: `t${i}`,
      value: {
        kind: 'raw_script' as const,
        bytes: bytesToHex(slice),
        in_arity: inArity,
        out_arity: outArity,
      },
    };
  });
  return {
    contractName: '_Recovered',
    properties: [],
    methods: [{ name: 'unlock', params: [], isPublic: true, body }],
  };
}
