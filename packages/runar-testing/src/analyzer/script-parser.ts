/**
 * Bitcoin Script parser — tokenizes hex-encoded scripts into structured
 * opcode lists for static analysis.
 *
 * Follows the same parsing logic as the VM disassembler but returns
 * structured ParsedOpcode[] instead of a display string.
 */

import { Opcode, opcodeName } from '../vm/opcodes.js';
import { hexToBytes } from '../vm/utils.js';
import type { RawScriptSpan } from './types.js';

// ---------------------------------------------------------------------------
// Synthetic raw-span sentinel
// ---------------------------------------------------------------------------

/**
 * Sentinel `opcode` value used for the synthetic opcode that stands in for
 * a `raw_script` byte range when `analyzeScript` is given the artifact's
 * `rawScriptSpans`. The value is outside the legal byte range (0..255) so
 * none of the existing `op.opcode === Opcode.OP_*` checks ever match it —
 * the synthetic step is naturally inert for IF/ELSE structure, CHECKSIG
 * hygiene, CODESEPARATOR concerns, and push-encoding analysis. Stack-effect
 * tracking reads `rawSpanArity` instead.
 */
export const RAW_SPAN_OPCODE = -1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ParsedOpcode {
  /** Byte offset of this opcode in the script. */
  offset: number;
  /**
   * Raw opcode byte value (0x00-0xff), or `RAW_SPAN_OPCODE` (-1) for the
   * synthetic step that stands in for a `raw_script` byte range.
   */
  opcode: number;
  /** Human-readable name (e.g., 'OP_ADD', 'OP_DUP', 'PUSH_20', 'RAW_SPAN'). */
  name: string;
  /** Push data bytes, if this is a push operation. */
  data?: Uint8Array;
  /** Total bytes consumed by this opcode (opcode byte + any length prefix + data). */
  size: number;
  /**
   * The push encoding used, if this is a push operation.
   * 'direct' = 0x01-0x4b (length is the opcode byte itself)
   * 'pushdata1' = OP_PUSHDATA1 (1-byte length prefix)
   * 'pushdata2' = OP_PUSHDATA2 (2-byte LE length prefix)
   * 'pushdata4' = OP_PUSHDATA4 (4-byte LE length prefix)
   * 'opN' = OP_0 through OP_16 / OP_1NEGATE (no data, number encoded in opcode)
   */
  pushEncoding?: 'direct' | 'pushdata1' | 'pushdata2' | 'pushdata4' | 'opN';
  /** For push-data: the actual data length (helps detect inefficient encoding). */
  dataLength?: number;
  /**
   * Stack effect of a synthetic raw-span step: `[pops, pushes]`. Present
   * only on the synthetic opcode produced by `collapseRawScriptSpans`.
   * Read by `getStackEffect` to keep depth tracking sound across the span.
   */
  rawSpanArity?: [pops: number, pushes: number];
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/**
 * Parse a hex-encoded Bitcoin Script into a list of structured opcodes.
 *
 * Handles truncated scripts gracefully — a truncated push operation is
 * returned with whatever data is available, and parsing stops.
 */
export function parseScript(hex: string): ParsedOpcode[] {
  const script = hexToBytes(hex);
  return parseScriptBytes(script);
}

/**
 * Parse raw script bytes into structured opcodes.
 */
export function parseScriptBytes(script: Uint8Array): ParsedOpcode[] {
  const opcodes: ParsedOpcode[] = [];
  let i = 0;

  while (i < script.length) {
    const startOffset = i;
    const byte = script[i]!;
    i++;

    // OP_0 (push empty byte array = numeric 0)
    if (byte === 0x00) {
      opcodes.push({
        offset: startOffset,
        opcode: byte,
        name: 'OP_0',
        size: 1,
        pushEncoding: 'opN',
        dataLength: 0,
      });
      continue;
    }

    // Direct push: 1-75 bytes (opcode IS the length)
    if (byte >= 0x01 && byte <= 0x4b) {
      const dataLen = byte;
      const available = Math.min(dataLen, script.length - i);
      const data = script.slice(i, i + available);
      i += available;
      opcodes.push({
        offset: startOffset,
        opcode: byte,
        name: `PUSH_${dataLen}`,
        data,
        size: 1 + available,
        pushEncoding: 'direct',
        dataLength: dataLen,
      });
      continue;
    }

    // OP_PUSHDATA1
    if (byte === Opcode.OP_PUSHDATA1) {
      if (i >= script.length) {
        opcodes.push({
          offset: startOffset,
          opcode: byte,
          name: 'OP_PUSHDATA1',
          size: 1,
          pushEncoding: 'pushdata1',
          dataLength: 0,
        });
        break;
      }
      const dataLen = script[i]!;
      i++;
      const available = Math.min(dataLen, script.length - i);
      const data = script.slice(i, i + available);
      i += available;
      opcodes.push({
        offset: startOffset,
        opcode: byte,
        name: 'OP_PUSHDATA1',
        data,
        size: 2 + available,
        pushEncoding: 'pushdata1',
        dataLength: dataLen,
      });
      continue;
    }

    // OP_PUSHDATA2
    if (byte === Opcode.OP_PUSHDATA2) {
      if (i + 1 >= script.length) {
        opcodes.push({
          offset: startOffset,
          opcode: byte,
          name: 'OP_PUSHDATA2',
          size: script.length - startOffset,
          pushEncoding: 'pushdata2',
          dataLength: 0,
        });
        break;
      }
      const dataLen = script[i]! | (script[i + 1]! << 8);
      i += 2;
      const available = Math.min(dataLen, script.length - i);
      const data = script.slice(i, i + available);
      i += available;
      opcodes.push({
        offset: startOffset,
        opcode: byte,
        name: 'OP_PUSHDATA2',
        data,
        size: 3 + available,
        pushEncoding: 'pushdata2',
        dataLength: dataLen,
      });
      continue;
    }

    // OP_PUSHDATA4
    if (byte === Opcode.OP_PUSHDATA4) {
      if (i + 3 >= script.length) {
        opcodes.push({
          offset: startOffset,
          opcode: byte,
          name: 'OP_PUSHDATA4',
          size: script.length - startOffset,
          pushEncoding: 'pushdata4',
          dataLength: 0,
        });
        break;
      }
      const dataLen =
        script[i]! |
        (script[i + 1]! << 8) |
        (script[i + 2]! << 16) |
        (script[i + 3]! << 24);
      i += 4;
      const available = Math.min(dataLen, script.length - i);
      const data = script.slice(i, i + available);
      i += available;
      opcodes.push({
        offset: startOffset,
        opcode: byte,
        name: 'OP_PUSHDATA4',
        data,
        size: 5 + available,
        pushEncoding: 'pushdata4',
        dataLength: dataLen,
      });
      continue;
    }

    // OP_1NEGATE (0x4f) — pushes -1
    if (byte === 0x4f) {
      opcodes.push({
        offset: startOffset,
        opcode: byte,
        name: 'OP_1NEGATE',
        size: 1,
        pushEncoding: 'opN',
        dataLength: 0,
      });
      continue;
    }

    // OP_1 through OP_16 (0x51-0x60) — push small integers
    if (byte >= 0x51 && byte <= 0x60) {
      opcodes.push({
        offset: startOffset,
        opcode: byte,
        name: opcodeName(byte),
        size: 1,
        pushEncoding: 'opN',
        dataLength: 0,
      });
      continue;
    }

    // All other opcodes
    opcodes.push({
      offset: startOffset,
      opcode: byte,
      name: opcodeName(byte),
      size: 1,
    });
  }

  return opcodes;
}

/**
 * Check if an opcode is a push operation (puts data on the stack).
 */
export function isPushOpcode(op: ParsedOpcode): boolean {
  return op.pushEncoding !== undefined;
}

/**
 * Check if an opcode is a flow control opcode.
 */
export function isFlowControl(op: ParsedOpcode): boolean {
  return (
    op.opcode === Opcode.OP_IF ||
    op.opcode === Opcode.OP_NOTIF ||
    op.opcode === Opcode.OP_ELSE ||
    op.opcode === Opcode.OP_ENDIF
  );
}

/**
 * Check if an opcode is a signature verification opcode.
 */
export function isCheckSigOpcode(op: ParsedOpcode): boolean {
  return (
    op.opcode === Opcode.OP_CHECKSIG ||
    op.opcode === Opcode.OP_CHECKSIGVERIFY ||
    op.opcode === Opcode.OP_CHECKMULTISIG ||
    op.opcode === Opcode.OP_CHECKMULTISIGVERIFY
  );
}

/**
 * Check if a parsed opcode is the synthetic raw-span step.
 */
export function isRawSpan(op: ParsedOpcode): boolean {
  return op.opcode === RAW_SPAN_OPCODE;
}

// ---------------------------------------------------------------------------
// Raw-span collapsing
// ---------------------------------------------------------------------------

/**
 * Rewrite a parsed opcode stream so that each byte range listed in `spans`
 * is replaced by a single synthetic `RAW_SPAN` opcode whose stack effect is
 * `(-inArity, +outArity)`.
 *
 * The synthetic opcode uses `RAW_SPAN_OPCODE` (-1), which intentionally
 * falls outside the legal byte range — every `op.opcode === Opcode.OP_*`
 * check in the analyzer becomes false for it, so the contents of the
 * span do not contribute to IF/ELSE structure detection, CODESEPARATOR
 * findings, push-encoding warnings, or CHECKSIG hygiene. Stack-effect
 * tracking reads `rawSpanArity` to keep depth analysis sound.
 *
 * Bytes inside a span are produced verbatim by the emit pass and are not
 * guaranteed to form a well-formed opcode stream (e.g. the user's `asm({
 * body })` may push arbitrary script bytes). The script parser will have
 * produced "best-effort" entries for them — those entries are discarded
 * by this function and replaced with the synthetic step.
 *
 * Spans are processed in offset order. Spans that overlap or escape the
 * parsed opcode bounds are silently clipped — the analyzer is a static
 * checker, not a validator, so we prefer "ignore weird inputs" over
 * throwing.
 */
export function collapseRawScriptSpans(
  opcodes: ParsedOpcode[],
  spans: RawScriptSpan[],
): ParsedOpcode[] {
  if (spans.length === 0) return opcodes;

  const sortedSpans = [...spans].sort((a, b) => a.offset - b.offset);
  const out: ParsedOpcode[] = [];

  let spanIdx = 0;
  for (const op of opcodes) {
    // Advance past spans we've already emitted (any span whose end is at or
    // before this opcode's offset is fully behind us).
    while (
      spanIdx < sortedSpans.length &&
      sortedSpans[spanIdx]!.offset + sortedSpans[spanIdx]!.length <= op.offset
    ) {
      spanIdx++;
    }

    if (spanIdx >= sortedSpans.length) {
      out.push(op);
      continue;
    }

    const span = sortedSpans[spanIdx]!;
    const spanEnd = span.offset + span.length;

    // Opcode entirely before the next span — keep it.
    if (op.offset + op.size <= span.offset) {
      out.push(op);
      continue;
    }

    // Opcode entirely inside a span — drop it; the synthetic step covers it.
    if (op.offset >= span.offset && op.offset + op.size <= spanEnd) {
      // Emit the synthetic step exactly once per span, when we first cross
      // its offset.
      if (
        out.length === 0 ||
        out[out.length - 1]!.opcode !== RAW_SPAN_OPCODE ||
        out[out.length - 1]!.offset !== span.offset
      ) {
        out.push({
          offset: span.offset,
          opcode: RAW_SPAN_OPCODE,
          name: 'RAW_SPAN',
          size: span.length,
          rawSpanArity: [span.inArity, span.outArity],
        });
      }
      continue;
    }

    // Partial overlap (opcode crosses a span boundary) — degenerate input.
    // The parser produced an opcode that straddles the span edge, which
    // means either the span is misaligned or the parser walked past the
    // span. Drop the partial opcode; the synthetic step still represents
    // the span's effect. If we haven't yet emitted the synthetic for this
    // span, emit it now.
    if (
      out.length === 0 ||
      out[out.length - 1]!.opcode !== RAW_SPAN_OPCODE ||
      out[out.length - 1]!.offset !== span.offset
    ) {
      out.push({
        offset: span.offset,
        opcode: RAW_SPAN_OPCODE,
        name: 'RAW_SPAN',
        size: span.length,
        rawSpanArity: [span.inArity, span.outArity],
      });
    }
  }

  // Any spans past the end of the parsed stream are silently dropped — they
  // can't have contributed any opcodes to drop, and emitting the synthetic
  // for an empty trailing span has no effect on the rest of the analysis.

  return out;
}
