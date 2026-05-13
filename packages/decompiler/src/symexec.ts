/**
 * Symbolic stack executor — opcode stream → SSA bindings.
 *
 * v0.1 status: recognizes the simplest terminal-assert patterns and emits
 * structured bindings for them. Falls back to a single `raw_block` binding
 * for anything else (which keeps the pipeline running end-to-end while the
 * full lifter is being written).
 *
 * Recognized patterns:
 *   [OP_TRUE]                                → assert(true)
 *   [OP_0]                                   → assert(false)
 *   [OP_TRUE, OP_VERIFY, ...trailing] where trailing recognized
 *
 * Everything else: emit one `raw_block` binding so the script body is
 * preserved as a /* RAW: <hex> *\/ comment.
 */

import type { AnnotatedOp } from './types.js';
import { bytesToHex } from 'runar-testing';

export type SsaBindingKind =
  | 'raw_block'
  | 'push'
  | 'builtin_call'
  | 'if'
  | 'assert_const'
  | 'assert_chain';

export interface SsaBinding {
  name: string;
  kind: SsaBindingKind;
  /** For raw_block: hex string of the original byte span. */
  rawHex?: string;
  /** For builtin_call: builtin name. */
  builtin?: string;
  /** Operand names (other SSA temps). */
  args?: string[];
  /** For assert_const: the literal boolean asserted. */
  constValue?: boolean;
  /** For assert_chain: ordered list of literal booleans, one per assert() call. */
  chainValues?: boolean[];
}

export interface SsaMethod {
  index: number;
  bindings: SsaBinding[];
  /** Name of the final binding (the method's result expression). */
  result: string;
}

function annotatedSpanToHex(ops: AnnotatedOp[]): string {
  const total = ops.reduce((sum, op) => sum + op.size, 0);
  const buf = new Uint8Array(total);
  let cursor = 0;
  for (const op of ops) {
    if (op.kind === 'op') {
      buf[cursor++] = op.byte;
      if (op.data !== undefined) {
        if (op.byte === 0x4c) buf[cursor++] = op.data.length & 0xff;
        else if (op.byte === 0x4d) {
          buf[cursor++] = op.data.length & 0xff;
          buf[cursor++] = (op.data.length >> 8) & 0xff;
        } else if (op.byte === 0x4e) {
          buf[cursor++] = op.data.length & 0xff;
          buf[cursor++] = (op.data.length >> 8) & 0xff;
          buf[cursor++] = (op.data.length >> 16) & 0xff;
          buf[cursor++] = (op.data.length >> 24) & 0xff;
        }
        buf.set(op.data, cursor);
        cursor += op.data.length;
      }
    } else {
      cursor += op.size;
    }
  }
  return bytesToHex(buf.subarray(0, cursor));
}

/**
 * Recognize a chain of assert(const_bool) calls.
 *
 * Compiled shape:
 *   - assert(true)                            → 0x51 (OP_TRUE)
 *   - assert(false)                           → 0x00 (OP_FALSE)
 *   - assert(b0); assert(b1); ...; assert(bN) →
 *       <push b0> OP_VERIFY <push b1> OP_VERIFY ... <push bN>
 *     where <push true> is 0x51 and <push false> is 0x00.
 *
 * Returns the recovered boolean list when the whole annotated span fits the
 * shape, null otherwise.
 */
function tryAssertChain(ops: AnnotatedOp[]): boolean[] | null {
  if (ops.length === 0) return null;
  const result: boolean[] = [];
  let i = 0;
  while (i < ops.length) {
    const a = ops[i]!;
    if (a.kind !== 'op') return null;
    let value: boolean;
    if (a.byte === 0x51) value = true;       // OP_TRUE
    else if (a.byte === 0x00) value = false; // OP_0 / OP_FALSE
    else return null;
    i++;
    if (i === ops.length) {
      // Final assert — value left on stack.
      result.push(value);
      return result;
    }
    const sep = ops[i]!;
    if (sep.kind !== 'op' || sep.byte !== 0x69) return null; // OP_VERIFY
    result.push(value);
    i++;
  }
  // Reached here only if the stream ended on OP_VERIFY, which is malformed.
  return null;
}

export function runSymbolic(ops: AnnotatedOp[], methodIndex: number): SsaMethod {
  if (ops.length === 0) {
    return { index: methodIndex, bindings: [], result: '_empty' };
  }

  const chain = tryAssertChain(ops);
  if (chain !== null) {
    if (chain.length === 1) {
      return {
        index: methodIndex,
        bindings: [{ name: '_t0', kind: 'assert_const', constValue: chain[0] }],
        result: '_t0',
      };
    }
    return {
      index: methodIndex,
      bindings: [{ name: '_t0', kind: 'assert_chain', chainValues: chain }],
      result: '_t0',
    };
  }

  // Fallback: preserve the raw bytes for human inspection.
  const hex = annotatedSpanToHex(ops);
  return {
    index: methodIndex,
    bindings: [{ name: '_raw0', kind: 'raw_block', rawHex: hex }],
    result: '_raw0',
  };
}
