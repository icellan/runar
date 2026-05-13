/**
 * Fingerprint matcher.
 *
 * Linear scan over the disassembled opcode stream. At each offset, the
 * longest matching fingerprint replaces the span with a `BuiltinCall`
 * marker. Greedy — collisions on overlapping fingerprints are rare in
 * practice; upgrade to DP if the coverage matrix reveals systematic
 * false-positives.
 */

import { bytesToHex } from 'runar-testing';
import type { AnnotatedOp, Op, BuiltinCall, FingerprintDB, Fingerprint } from './types.js';
import { entriesByLengthDesc } from './fingerprints.js';

/** Re-encode a sequence of disassembled ops to canonical opcode-byte hex. */
function opsToHex(ops: Op[]): string {
  const total = ops.reduce((sum, op) => sum + op.size, 0);
  const buf = new Uint8Array(total);
  let cursor = 0;
  for (const op of ops) {
    buf[cursor++] = op.byte;
    if (op.data !== undefined) {
      // Skip length prefix for OP_PUSHDATA{1,2,4} — those bytes follow the
      // opcode and are already counted in op.size, but they aren't in op.data.
      // For direct pushes (1..75) there is no length prefix.
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
  }
  return bytesToHex(buf.subarray(0, cursor));
}

/**
 * Find the count of ops whose total byte length equals `targetLen`. Returns
 * -1 if no exact match boundary exists (the fingerprint doesn't align with
 * the op stream at this offset).
 */
function opCountForByteLen(ops: Op[], start: number, targetLen: number): number {
  let acc = 0;
  for (let i = start; i < ops.length; i++) {
    acc += ops[i]!.size;
    if (acc === targetLen) return i - start + 1;
    if (acc > targetLen) return -1;
  }
  return -1;
}

export interface MatchOptions {
  /** Optional pre-loaded DB. If absent, the matcher acts as a no-op. */
  db?: FingerprintDB;
}

export function matchFingerprints(ops: Op[], opts: MatchOptions = {}): AnnotatedOp[] {
  const db = opts.db;
  if (!db || db.entries.length === 0) {
    return ops.map(op => ({ ...op, kind: 'op' as const }));
  }
  const sorted = entriesByLengthDesc(db);
  const out: AnnotatedOp[] = [];
  let i = 0;

  while (i < ops.length) {
    let matched: { entry: Fingerprint; consume: number; alternatives: string[] } | null = null;

    for (const entry of sorted) {
      const consume = opCountForByteLen(ops, i, entry.length);
      if (consume <= 0) continue;
      const slice = ops.slice(i, i + consume);
      const hex = opsToHex(slice);
      if (hex === entry.normalizedHex) {
        if (matched === null) {
          matched = { entry, consume, alternatives: [] };
          // Continue scanning at this length to collect other entries with
          // an identical normalizedHex (same span, different builtin name —
          // refinement strategy 1 cycles through these on a byte-diff).
          continue;
        }
        if (matched.entry.length === entry.length && entry.name !== matched.entry.name) {
          // Same-span sibling: a true alternative the refinement loop can try.
          matched.alternatives.push(entry.name);
          continue;
        }
        // Shorter strict-prefix hit: ignore (longest-first sort already
        // surfaced the longest candidate).
      }
    }

    if (matched) {
      const call: BuiltinCall = {
        kind: 'builtin_call',
        name: matched.entry.name,
        arity: matched.entry.arity,
        offset: ops[i]!.offset,
        size: matched.entry.length,
        alternatives: matched.alternatives.length > 0 ? matched.alternatives : undefined,
      };
      out.push(call);
      i += matched.consume;
    } else {
      out.push({ ...ops[i]!, kind: 'op' });
      i += 1;
    }
  }

  return out;
}
