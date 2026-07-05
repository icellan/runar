/**
 * Push-element size characterization (TS-GAP-010, Task 6.3).
 *
 * The classic pre-Genesis Bitcoin Script rule caps a single push element at
 * MAX_SCRIPT_ELEMENT_SIZE = 520 bytes. Rúnar, however, targets **Chronicle**
 * (the post-Genesis BSV node variant this repo compiles for — see
 * `conformance/script_execution_test.go`, which executes every spend under
 * `interpreter.WithAfterChronicle()`). Chronicle **lifts** the single-element
 * cap (it is raised to MaxInt32), so a push element larger than 520 bytes is
 * perfectly valid and spendable on the target network. The repo's `ScriptVM`
 * likewise enforces no element-size cap.
 *
 * Therefore the compiler CORRECTLY emits an oversized `ByteString` literal as a
 * single push element with no diagnostic and no chunking: adding a 520-byte
 * rejection guard would break legitimate large-literal contracts (large data
 * blobs, embedded keys, etc.) that spend fine on Chronicle. This suite pins
 * that intended behavior — and doubles as the tripwire that would fire if a
 * pre-Genesis target were ever adopted (at which point a compile-time guard or
 * multi-push chunking, plus the matching consensus limits, would be required).
 *
 * The strict pre-Genesis 520/1000/4-byte boundaries themselves are covered
 * adversarially by `conformance/boundary_test.go` (which runs its corpus under
 * the before-genesis engine config to prove those limits are enforceable).
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/** MAX_SCRIPT_ELEMENT_SIZE — the pre-Genesis single-element cap. Lifted on the
 *  Chronicle target this compiler emits for. */
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

describe('push-element size (Chronicle target — no 520 cap)', () => {
  it('a 520-byte literal emits a single element of exactly 520 bytes', () => {
    const res = compile(contractWithLiteral(520), { fileName: 'BigPush.runar.ts' });
    expect(res.success).toBe(true);
    expect(errors(res.diagnostics)).toEqual([]);
    expect(maxPushElement(res.artifact!.script)).toBe(MAX_SCRIPT_ELEMENT_SIZE);
  });

  it('a 600-byte literal compiles clean and emits a single >520-byte element (valid on Chronicle)', () => {
    const res = compile(contractWithLiteral(600), { fileName: 'BigPush.runar.ts' });

    // CORRECT behavior for the Chronicle target: no spurious guard, no error,
    // emitted as a single push element. (A pre-Genesis target would instead
    // require a compile error or chunking — this assertion would then flip.)
    expect(res.success).toBe(true);
    expect(errors(res.diagnostics)).toEqual([]);
    expect(maxPushElement(res.artifact!.script)).toBe(600);
    expect(maxPushElement(res.artifact!.script)).toBeGreaterThan(MAX_SCRIPT_ELEMENT_SIZE);
  });
});
