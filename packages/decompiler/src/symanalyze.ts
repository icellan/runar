/**
 * Symbolic region analyzer — recovers *meaning* from an unrecognized span
 * without lifting it to code. Uses symExec to confirm micro-idioms:
 *
 *   - `le_int_decode` — `<push 00> OP_CAT OP_BIN2NUM`: interpret a byte-slice
 *     as an unsigned little-endian integer (the script pads with a 0x00 sign
 *     byte, then BIN2NUM). Confirmed symbolically as `num(X || 0x00)`.
 *   - `varint_read` — `OP_GREATERTHAN OP_IF <n> OP_ELSE <n> OP_ENDIF OP_SPLIT`:
 *     the CompactSize discriminant that picks a 2- or 4-byte extended length
 *     and splits it off.
 *
 * The bytes are NOT modified; findings are attached to the asm island as
 * recovered meaning.
 */

import { bytesToHex } from 'runar-testing';
import type { Op } from './types.js';
import { symExec } from './symcore.js';

export interface RegionFinding {
  kind: 'le_int_decode' | 'varint_read';
  offset: number;
}

/** A tandem-repeated op-block — an unrolled loop. */
export interface LoopRepeat {
  startOffset: number;
  endOffset: number;
  /** Opcodes per iteration. */
  period: number;
  /** Iteration count. */
  repeats: number;
}

export interface RegionAnalysis {
  findings: RegionFinding[];
  loops: LoopRepeat[];
  summary: string;
}

function opKey(op: Op): string {
  return op.data ? `${op.name}:${bytesToHex(op.data)}` : op.name;
}

function blockEq(ops: Op[], a: number, b: number, p: number): boolean {
  for (let k = 0; k < p; k++) {
    if (opKey(ops[a + k]!) !== opKey(ops[b + k]!)) return false;
  }
  return true;
}

/**
 * Find tandem-repeated op-blocks (adjacent identical iterations) — the residue
 * of a loop the source compiler unrolled. Greedy, max-coverage at each
 * position; perf is a non-goal so the O(n²) scan is fine.
 */
export function detectRepeats(
  ops: Op[],
  startIdx: number,
  endIdx: number,
  opts: { minPeriod?: number; minRepeats?: number; minCoverage?: number } = {},
): LoopRepeat[] {
  const minPeriod = opts.minPeriod ?? 4;
  const minRepeats = opts.minRepeats ?? 2;
  const minCoverage = opts.minCoverage ?? 8;
  const results: LoopRepeat[] = [];
  let i = startIdx;
  while (i < endIdx) {
    let best: { period: number; repeats: number } | null = null;
    const maxPeriod = Math.floor((endIdx - i) / 2);
    for (let p = minPeriod; p <= maxPeriod; p++) {
      let r = 1;
      while (i + (r + 1) * p <= endIdx && blockEq(ops, i, i + r * p, p)) r++;
      if (r >= minRepeats) {
        const cov = p * r;
        if (cov >= minCoverage && (!best || cov > best.period * best.repeats)) {
          best = { period: p, repeats: r };
        }
      }
    }
    if (best) {
      const lastOp = ops[i + best.period * best.repeats - 1]!;
      results.push({
        startOffset: ops[i]!.offset,
        endOffset: lastOp.offset + lastOp.size,
        period: best.period,
        repeats: best.repeats,
      });
      i += best.period * best.repeats;
    } else {
      i++;
    }
  }
  return results;
}

function isPush00(op: Op | undefined): boolean {
  return op?.data !== undefined && op.data.length === 1 && op.data[0] === 0x00;
}

/** Confirm `ops[i..i+3]` is the `<00> CAT BIN2NUM` LE-decode micro-idiom. */
function confirmsLeDecode(ops: Op[], i: number): boolean {
  if (!isPush00(ops[i]) || ops[i + 1]?.name !== 'OP_CAT' || ops[i + 2]?.name !== 'OP_BIN2NUM') {
    return false;
  }
  const st = symExec(ops.slice(i, i + 3), { initialStack: ['x'] });
  const top = st.stack[st.stack.length - 1];
  return (
    st.modeled &&
    top?.t === 'bin2num' &&
    top.v.t === 'cat' &&
    top.v.b.t === 'const' &&
    top.v.b.hex === '00'
  );
}

/** Detect the CompactSize varint width-select + split at `ops[i]`. */
function isVarintRead(ops: Op[], i: number): boolean {
  return (
    ops[i]?.name === 'OP_GREATERTHAN' &&
    ops[i + 1]?.name === 'OP_IF' &&
    ops[i + 3]?.name === 'OP_ELSE' &&
    ops[i + 5]?.name === 'OP_ENDIF' &&
    ops[i + 6]?.name === 'OP_SPLIT'
  );
}

/** Value roles inferred from field widths (a standard parsing heuristic). */
export interface FieldRoles {
  /** 8-byte little-endian reads — token amounts / satoshi values. */
  amount8: number;
  /** 36-byte reads — outpoints (txid32 || vout4). */
  outpoint36: number;
}

export function classifyFields(ops: Op[], startIdx: number, endIdx: number): FieldRoles {
  let amount8 = 0;
  let outpoint36 = 0;
  for (let i = startIdx; i < endIdx; i++) {
    if (ops[i]!.name === 'OP_8' && ops[i + 1]?.name === 'OP_SPLIT') amount8++;
    const d = ops[i]!.data ? bytesToHex(ops[i]!.data!) : null;
    if (d === '24' && ops[i + 1]?.name === 'OP_SPLIT') outpoint36++;
  }
  return { amount8, outpoint36 };
}

export function analyzeRegion(ops: Op[], startIdx: number, endIdx: number): RegionAnalysis {
  const findings: RegionFinding[] = [];
  for (let i = startIdx; i < endIdx; i++) {
    if (confirmsLeDecode(ops, i)) {
      findings.push({ kind: 'le_int_decode', offset: ops[i]!.offset });
    }
    if (isVarintRead(ops, i)) {
      findings.push({ kind: 'varint_read', offset: ops[i]!.offset });
    }
  }
  const loops = detectRepeats(ops, startIdx, endIdx);
  const le = findings.filter((f) => f.kind === 'le_int_decode').length;
  const vi = findings.filter((f) => f.kind === 'varint_read').length;
  let summary = `${le} little-endian integer decode${le === 1 ? '' : 's'}, ${vi} CompactSize varint read${vi === 1 ? '' : 's'}`;
  if (loops.length > 0) {
    const desc = loops.map((l) => `${l.repeats}×${l.period}op`).join(', ');
    summary += `; ${loops.length} unrolled loop${loops.length === 1 ? '' : 's'} (${desc})`;
  }
  const roles = classifyFields(ops, startIdx, endIdx);
  if (roles.amount8 > 0 || roles.outpoint36 > 0) {
    const parts: string[] = [];
    if (roles.amount8 > 0) parts.push(`${roles.amount8} 8-byte amount${roles.amount8 === 1 ? '' : 's'}`);
    if (roles.outpoint36 > 0) parts.push(`${roles.outpoint36} 36-byte outpoint${roles.outpoint36 === 1 ? '' : 's'}`);
    summary += `; value roles: ${parts.join(', ')}`;
  }
  return { findings, loops, summary };
}
