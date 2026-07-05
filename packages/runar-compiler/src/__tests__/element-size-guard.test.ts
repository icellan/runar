/**
 * Oversized push-element guard (TS-GAP-010, Task 6.3).
 *
 * A single Bitcoin Script push element larger than MAX_SCRIPT_ELEMENT_SIZE
 * (520 bytes) is unspendable under a consensus rule that enforces that cap.
 * This suite pins the compiler's CURRENT behavior when a `ByteString` literal
 * exceeds 520 bytes.
 *
 * FINDING (live): the compiler has NO compile-time guard and does NOT chunk
 * the literal — it emits it as a single push element (OP_PUSHDATA2 + N bytes).
 * A 600-byte literal produces one 600-byte push element with `success: true`
 * and no diagnostic. These tests DOCUMENT that gap (they do not silence it):
 * the assertions below encode "the oversized push exists today". When a guard
 * lands — either a compile error or multi-push chunking — these tests will
 * fail loudly and must be flipped to assert the fixed invariant
 * (`maxPushElement <= 520`).
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/** MAX_SCRIPT_ELEMENT_SIZE — the classic pre-Genesis single-element cap the
 *  finding references. */
const MAX_SCRIPT_ELEMENT_SIZE = 520;

/** Largest single push-element byte length in a compiled script (0 if none). */
function maxPushElement(scriptHex: string): number {
  const bytes = Buffer.from(scriptHex, 'hex');
  let i = 0;
  let max = 0;
  while (i < bytes.length) {
    const b = bytes[i++]!;
    let len: number | null = null;
    if (b >= 0x01 && b <= 0x4b) {
      len = b;
    } else if (b === 0x4c) {
      // OP_PUSHDATA1
      len = bytes[i]!;
      i += 1;
    } else if (b === 0x4d) {
      // OP_PUSHDATA2
      len = bytes[i]! | (bytes[i + 1]! << 8);
      i += 2;
    } else if (b === 0x4e) {
      // OP_PUSHDATA4
      len = bytes[i]! | (bytes[i + 1]! << 8) | (bytes[i + 2]! << 16) | (bytes[i + 3]! << 24);
      i += 4;
    } else {
      // Opcode with no inline data.
      continue;
    }
    if (len > max) max = len;
    i += len;
  }
  return max;
}

function contractWithLiteral(byteLen: number): string {
  const hex = 'ab'.repeat(byteLen); // byteLen bytes as hex
  return `
import { SmartContract, ByteString, assert } from 'runar-lang';

export class BigPush extends SmartContract {
  constructor() { super(); }
  public check(x: ByteString): void {
    assert(x === ("${hex}" as ByteString));
  }
}
`;
}

function errors(diagnostics: { severity: string }[]): { severity: string }[] {
  return diagnostics.filter((d) => d.severity === 'error');
}

describe('oversized push-element guard (TS-GAP-010)', () => {
  it('boundary control: a 520-byte literal emits a single element of exactly 520 bytes (at the cap)', () => {
    const res = compile(contractWithLiteral(520), { fileName: 'BigPush.runar.ts' });
    expect(res.success).toBe(true);
    expect(errors(res.diagnostics)).toEqual([]);
    expect(maxPushElement(res.artifact!.script)).toBe(MAX_SCRIPT_ELEMENT_SIZE);
  });

  it('DOCUMENTS GAP: a 600-byte literal is emitted as a single >520-byte push with no compile-time guard', () => {
    const res = compile(contractWithLiteral(600), { fileName: 'BigPush.runar.ts' });

    // Current behavior: compiles clean (no error), no chunking.
    expect(res.success).toBe(true);
    expect(errors(res.diagnostics)).toEqual([]);

    const largest = maxPushElement(res.artifact!.script);

    // The intended/desired behavior would be EITHER a compile error OR no
    // element over 520 bytes. Neither holds today, so we pin the gap: the
    // compiler emits a single 600-byte push element (unspendable under a
    // 520-byte consensus cap). If a guard is added, flip these to
    // `expect(largest).toBeLessThanOrEqual(MAX_SCRIPT_ELEMENT_SIZE)`.
    expect(largest).toBeGreaterThan(MAX_SCRIPT_ELEMENT_SIZE);
    expect(largest).toBe(600);
  });
});
