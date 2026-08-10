/**
 * Control-flow tree — structural backbone for the native-if renderer.
 *
 * Bitcoin Script control flow is flat: `OP_IF / OP_NOTIF … [OP_ELSE …] OP_ENDIF`
 * with implicit nesting by balance. This module recovers that nesting into a
 * tree of `linear` runs (straight-line op spans) and `if` blocks (with `then` /
 * `else` children). The native-if renderer walks the tree to emit real Rúnar
 * `if (cond) { … } else { … }`; the symbolic condition recovery keys off the
 * `linear` run that precedes each `if`.
 *
 * The tree is a pure *re-view* of the same bytes — `flattenSpans` reconstructs
 * the original byte stream exactly (linear leaves + IF/ELSE/ENDIF marker bytes),
 * which keeps the byte-exact asm-island tiling and this structural view in lock-
 * step. Unbalanced control flow (no matching ENDIF) is never thrown on: the
 * stray marker is folded into a linear run so the tree still tiles.
 */

import type { Op } from './types.js';

export interface CFLinear {
  kind: 'linear';
  /** op index range [startIndex, endIndex). */
  startIndex: number;
  endIndex: number;
  /** byte offset range [start, end). */
  span: [number, number];
}

export interface CFIf {
  kind: 'if';
  /** `if` ⇒ run THEN when truthy; `notif` ⇒ run THEN when falsy. */
  op: 'if' | 'notif';
  /** op index of OP_IF/OP_NOTIF. */
  ifIndex: number;
  /** op index of OP_ELSE, or -1. */
  elseIndex: number;
  /** op index of OP_ENDIF. */
  endIndex: number;
  /** byte offset of OP_ELSE, or -1 (kept so `flattenSpans` needs no ops). */
  elseByte: number;
  /** byte offset range [start, end) covering OP_IF … OP_ENDIF inclusive. */
  span: [number, number];
  then: CFNode[];
  else: CFNode[];
}

export type CFNode = CFLinear | CFIf;

/** Find the depth-0 OP_ELSE (if any) and OP_ENDIF for the OP_IF/OP_NOTIF at `ifIdx`. */
function matchBranch(
  ops: Op[],
  ifIdx: number,
  end: number,
): { elseIdx: number; endIdx: number } | null {
  let depth = 0;
  let elseIdx = -1;
  for (let j = ifIdx + 1; j < end; j++) {
    const n = ops[j]!.name;
    if (n === 'OP_IF' || n === 'OP_NOTIF') depth++;
    else if (n === 'OP_ENDIF') {
      if (depth === 0) return { elseIdx, endIdx: j };
      depth--;
    } else if (n === 'OP_ELSE' && depth === 0) {
      elseIdx = j;
    }
  }
  return null;
}

function linearNode(ops: Op[], startIndex: number, endIndex: number): CFLinear {
  const startOff = ops[startIndex]!.offset;
  const last = ops[endIndex - 1]!;
  return { kind: 'linear', startIndex, endIndex, span: [startOff, last.offset + last.size] };
}

/**
 * Parse `ops[start, end)` into a control-flow tree, with node indices ABSOLUTE
 * into `ops` (so callers can mix sub-range trees with the full op stream). Used
 * by the structured renderer to parse control flow per recognized-idiom segment.
 */
export function parseRange(ops: Op[], start: number, end: number): CFNode[] {
  const nodes: CFNode[] = [];
  let linStart = start;
  let i = start;
  const flushLinear = (until: number) => {
    if (until > linStart) nodes.push(linearNode(ops, linStart, until));
  };
  while (i < end) {
    const name = ops[i]!.name;
    if (name === 'OP_IF' || name === 'OP_NOTIF') {
      const br = matchBranch(ops, i, end);
      if (!br) {
        // Unbalanced — treat the marker as a plain op so the tree still tiles.
        i++;
        continue;
      }
      flushLinear(i);
      const thenEnd = br.elseIdx >= 0 ? br.elseIdx : br.endIdx;
      const thenNodes = parseRange(ops, i + 1, thenEnd);
      const elseNodes = br.elseIdx >= 0 ? parseRange(ops, br.elseIdx + 1, br.endIdx) : [];
      const endifOp = ops[br.endIdx]!;
      nodes.push({
        kind: 'if',
        op: name === 'OP_IF' ? 'if' : 'notif',
        ifIndex: i,
        elseIndex: br.elseIdx,
        endIndex: br.endIdx,
        elseByte: br.elseIdx >= 0 ? ops[br.elseIdx]!.offset : -1,
        span: [ops[i]!.offset, endifOp.offset + endifOp.size],
        then: thenNodes,
        else: elseNodes,
      });
      i = br.endIdx + 1;
      linStart = i;
      continue;
    }
    // A stray OP_ELSE/OP_ENDIF at this level (unbalanced input): fold into linear.
    i++;
  }
  flushLinear(end);
  return nodes;
}

/** Parse a full op stream into a control-flow tree. Never throws. */
export function parseControlFlow(ops: Op[]): CFNode[] {
  if (ops.length === 0) return [];
  return parseRange(ops, 0, ops.length);
}

/**
 * Reconstruct the exact byte stream from the tree: linear leaves contribute
 * their bytes; each `if` contributes its OP_IF/OP_NOTIF byte, then-children,
 * optional OP_ELSE byte, else-children, and OP_ENDIF byte — in source order.
 * Equal to the input bytes iff the tree faithfully covers the script.
 */
export function flattenSpans(tree: CFNode[], bytes: Uint8Array): Uint8Array {
  const out: number[] = [];
  const walk = (nodes: CFNode[]) => {
    for (const n of nodes) {
      if (n.kind === 'linear') {
        for (let k = n.span[0]; k < n.span[1]; k++) out.push(bytes[k]!);
        continue;
      }
      out.push(bytes[n.span[0]]!); // OP_IF / OP_NOTIF
      walk(n.then);
      if (n.elseIndex >= 0) out.push(bytes[n.elseByte]!); // OP_ELSE
      walk(n.else);
      out.push(bytes[n.span[1] - 1]!); // OP_ENDIF
    }
  };
  walk(tree);
  return Uint8Array.from(out);
}
