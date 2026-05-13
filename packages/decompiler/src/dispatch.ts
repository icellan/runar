/**
 * Multi-method dispatch recognizer.
 *
 * Splits a Bitcoin Script byte stream produced by Rúnar's TS compiler into N
 * per-method op streams by recognizing the dispatch preamble emitted at
 * `06-emit.ts:605-637` (`emitMethodDispatch`).
 *
 * For N public methods, the compiler emits:
 *
 *   methods 0..N-2:  OP_DUP <push i> OP_NUMEQUAL OP_IF OP_DROP <body_i> OP_ELSE
 *   method N-1:      <push N-1> OP_NUMEQUALVERIFY <body_N-1>
 *   (closing)        OP_ENDIF × (N-1)
 *
 * Single-method scripts have no dispatch glue — we pass through with
 * methodCount = 1.
 */

import type { Op, DispatchResult, MethodStream } from './types.js';
import { decodeScriptNumber } from 'runar-testing';

/**
 * Read the integer pushed by a single-op (`OP_1..OP_16`, `OP_1NEGATE`, `OP_0`)
 * or a direct push opcode. Returns null if `op` is not a small-int push.
 */
function readSmallInt(op: Op | undefined): bigint | null {
  if (!op) return null;
  if (op.name === 'OP_0') return 0n;
  if (op.byte >= 0x51 && op.byte <= 0x60) return BigInt(op.byte - 0x50);
  if (op.name === 'OP_1NEGATE') return -1n;
  if (op.data !== undefined) {
    return decodeScriptNumber(op.data);
  }
  return null;
}

export function splitMethods(ops: Op[]): DispatchResult {
  // No ops at all → empty single method.
  if (ops.length === 0) {
    return { methodCount: 1, methods: [{ index: 0, ops: [] }] };
  }

  // Detect the asymmetric preamble by looking for the leading shape:
  //   OP_DUP <push 0> OP_NUMEQUAL OP_IF OP_DROP ...
  // If absent, treat as single-method.
  if (!isDispatchStart(ops, 0, 0)) {
    return { methodCount: 1, methods: [{ index: 0, ops } ] };
  }

  const methods: MethodStream[] = [];
  let i = 0;
  let methodIndex = 0;

  while (true) {
    // Each non-last method consumes 5 prefix ops: OP_DUP, <push i>, OP_NUMEQUAL, OP_IF, OP_DROP
    if (!isDispatchStart(ops, i, methodIndex)) break;
    i += 5;

    // Walk forward until the matching OP_ELSE at the same nesting depth.
    const { bodyEnd, sawElse } = scanToBranchClose(ops, i);
    if (!sawElse) break; // malformed; abort dispatch detection

    const body = ops.slice(i, bodyEnd);
    methods.push({ index: methodIndex, ops: body });

    i = bodyEnd + 1; // skip the OP_ELSE itself
    methodIndex++;

    // Now check whether the next thing is another OP_DUP-style preamble,
    // OR the terminal preamble `<push N-1> OP_NUMEQUALVERIFY <body>`.
    if (isDispatchStart(ops, i, methodIndex)) {
      continue;
    }

    // Try terminal form: <push idx> OP_NUMEQUALVERIFY <body> [OP_ENDIF × prior count]
    const pushVal = readSmallInt(ops[i]);
    if (pushVal !== null && pushVal === BigInt(methodIndex) && ops[i + 1]?.name === 'OP_NUMEQUALVERIFY') {
      i += 2;
      // The body runs until the script tail of OP_ENDIFs.
      const tailEndifs = methodIndex; // there should be exactly methodIndex trailing OP_ENDIFs
      const bodyTerminalEnd = ops.length - tailEndifs;
      if (bodyTerminalEnd < i) break;
      // Verify the tail is all OP_ENDIFs.
      let ok = true;
      for (let j = bodyTerminalEnd; j < ops.length; j++) {
        if (ops[j]!.name !== 'OP_ENDIF') { ok = false; break; }
      }
      if (!ok) break;
      const tailBody = ops.slice(i, bodyTerminalEnd);
      methods.push({ index: methodIndex, ops: tailBody });
      return { methodCount: methods.length, methods };
    }

    // Neither continuation nor terminal — treat as failed match, fall back.
    break;
  }

  // Fallback: dispatch detection failed mid-stream.
  return { methodCount: 1, methods: [{ index: 0, ops }] };
}

function isDispatchStart(ops: Op[], i: number, expectedIndex: number): boolean {
  if (i + 4 >= ops.length) return false;
  if (ops[i]!.name !== 'OP_DUP') return false;
  const pushedIdx = readSmallInt(ops[i + 1]);
  if (pushedIdx === null || pushedIdx !== BigInt(expectedIndex)) return false;
  if (ops[i + 2]!.name !== 'OP_NUMEQUAL') return false;
  if (ops[i + 3]!.name !== 'OP_IF') return false;
  if (ops[i + 4]!.name !== 'OP_DROP') return false;
  return true;
}

/**
 * Starting just after an OP_IF/OP_DROP preamble, find the matching OP_ELSE
 * at the same nesting depth. Returns the index of that OP_ELSE and a flag.
 *
 * Nested user-level OP_IF/OP_ELSE/OP_ENDIF blocks are respected via depth
 * counting.
 */
function scanToBranchClose(ops: Op[], start: number): { bodyEnd: number; sawElse: boolean } {
  let depth = 0;
  for (let j = start; j < ops.length; j++) {
    const name = ops[j]!.name;
    if (name === 'OP_IF' || name === 'OP_NOTIF') depth++;
    else if (name === 'OP_ENDIF') {
      if (depth === 0) return { bodyEnd: j, sawElse: false };
      depth--;
    } else if (name === 'OP_ELSE' && depth === 0) {
      return { bodyEnd: j, sawElse: true };
    }
  }
  return { bodyEnd: ops.length, sawElse: false };
}
