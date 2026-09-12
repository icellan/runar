import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, runDifferentialExecution } from 'runar-testing';

/**
 * R-106 / CL-GAP-047 — `go-dsl-bytestring-literal` was tested in the Go tier
 * only, and in none of the other eight formats.
 *
 * It exists for the bare ByteString literal: `"006a" === this.expected`, with no
 * `toByteString(...)` wrapper. That spelling is how the Go DSL surface writes
 * bytes, and every frontend has to agree it is BYTES and not a four-character
 * string — a literal silently read as text compares unequal to the same bytes
 * and the contract becomes unspendable.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'GoDslBytestringLiteral.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const EXPECTED = '006a';

describe('GoDslBytestringLiteral (a bare ByteString literal)', () => {
  it('accepts when the sum matches and the literal matches', () => {
    const c = TestContract.fromSource(source, { target: 10n, expected: EXPECTED }, FILE);
    const r = c.call('check', { a: 4n, b: 6n });
    expect(r.success, r.error).toBe(true);
  });

  it('rejects a wrong sum', () => {
    const c = TestContract.fromSource(source, { target: 10n, expected: EXPECTED }, FILE);
    expect(c.call('check', { a: 4n, b: 7n }).success).toBe(false);
  });

  it('rejects when the deployed bytes differ from the literal', () => {
    const c = TestContract.fromSource(source, { target: 10n, expected: '006b' }, FILE);
    expect(
      c.call('check', { a: 4n, b: 6n }).success,
      'the literal comparison must be a real byte comparison',
    ).toBe(false);
  });

  it('rejects bytes that merely LOOK like the literal text', () => {
    // "006a" as ASCII text, not as hex bytes. A frontend that read the literal
    // as a string rather than as bytes would accept this and reject the real
    // 0x00 0x6a — the exact confusion this example guards.
    const asAscii = Buffer.from('006a', 'utf8').toString('hex');
    expect(asAscii).not.toBe(EXPECTED);
    const c = TestContract.fromSource(source, { target: 10n, expected: asAscii }, FILE);
    expect(c.call('check', { a: 4n, b: 6n }).success).toBe(false);
  });

  it('the interpreter and the ScriptVM agree on the accepting case', () => {
    const r = runDifferentialExecution({
      source,
      fileName: FILE,
      method: 'check',
      args: [4n, 6n],
      constructorArgs: { target: 10n, expected: EXPECTED },
    });
    expect(r.agrees, `interpreter=${r.interpreterAccepted} vm=${r.vmAccepted}`).toBe(true);
  });
});
