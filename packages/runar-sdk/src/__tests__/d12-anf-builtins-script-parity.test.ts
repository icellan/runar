/**
 * D12 BM-F5 / BM-F6 / reverseBytes: the SDK ANF interpreter (what
 * `prepareCall` uses to derive a continuation) must refuse exactly where the
 * compiled script aborts, and compute what the script computes otherwise.
 *
 * Every row is run twice: the compiled locking script on @bsv/sdk Spend
 * (ScriptExecutionContract, the oracle), and `executeStrict` on the same
 * contract's ANF (the subject). The test asserts the two verdicts agree.
 *
 * - BM-F5: `num2bin(v, w)` with w too narrow for v (or w < 0) aborts on
 *   chain (OP_NUM2BIN); the interpreter used to truncate.
 * - BM-F6: a non-minimally encoded number (`1 >> 1` leaves [0x00]) passed to
 *   a numeric builtin aborts on chain; the interpreter only checked bin_op /
 *   unary_op operands. num2bin's VALUE operand is the exception: OP_NUM2BIN
 *   does not require it minimal, so it must keep working.
 * - reverseBytes: the compiled script reverses at most 520 bytes; the
 *   interpreter must refuse a longer input instead of reversing all of it.
 *
 * Does not prove: other tiers, or builtins not listed here.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { ScriptExecutionContract } from 'runar-testing';
import { executeStrict } from '../anf-interpreter.js';

type Row = { label: string; expr: string; types: string[]; args: unknown[] };

// The last parameter is always the expected value `e`.
function paramNames(n: number): string[] {
  return [...['a', 'b', 'c'].slice(0, n - 1), 'e'];
}

function contractFor(expr: string, types: string[]): string {
  const names = paramNames(types.length);
  const params = types.map((t, i) => `${names[i]}: ${t}`).join(', ');
  return `import { SmartContract, assert, ByteString, abs, min, max, within, clamp, sign, pow, mulDiv, num2bin, reverseBytes, sqrt, gcd, log2, divmod, safediv, safemod, percentOf, bool, split, left, right, substr } from 'runar-lang';

export class P extends SmartContract {
  readonly k: bigint;
  constructor(k: bigint) { super(k); this.k = k; }
  public f(${params}) { assert((${expr}) === e); }
}
`;
}

function verdicts(row: Row): { script: boolean; sdk: boolean; sdkError?: string } {
  const src = contractFor(row.expr, row.types);
  const r = compile(src, { fileName: 'P.runar.ts', disableConstantFolding: true });
  if (!r.success || !r.anf) throw new Error(r.diagnostics.map((d) => d.message).join('; '));
  const script = ScriptExecutionContract.fromSource(src, { k: 0n }, 'P.runar.ts')
    .execute('f', row.args).success;
  const names = paramNames(row.args.length);
  const named = Object.fromEntries(row.args.map((v, i) => [names[i]!, v]));
  try {
    executeStrict(r.anf as never, 'f', {}, named, [0n]);
    return { script, sdk: true };
  } catch (e) {
    return { script, sdk: false, sdkError: (e as Error).message };
  }
}

const I = 'bigint';
const B = 'ByteString';
const rev = (hex: string) => hex.match(/../g)!.reverse().join('');
const bytes = (n: number) => Array.from({ length: n }, (_, i) => (i % 251 + 1).toString(16).padStart(2, '0')).join('');

const ROWS: Array<Row & { script: boolean }> = [
  // BM-F5: narrow width aborts on chain.
  { label: 'num2bin(40000, 2)', expr: 'num2bin(a, b)', types: [I, I, B], args: [40000n, 2n, '409c'], script: false },
  { label: 'num2bin(128, 1)', expr: 'num2bin(a, b)', types: [I, I, B], args: [128n, 1n, '80'], script: false },
  { label: 'num2bin(1, 0)', expr: 'num2bin(a, b)', types: [I, I, B], args: [1n, 0n, ''], script: false },
  { label: 'num2bin(2^31, 4)', expr: 'num2bin(a, b)', types: [I, I, B], args: [2n ** 31n, 4n, '00000080'], script: false },
  // controls
  { label: 'num2bin(255, 2) = ff00', expr: 'num2bin(a, b)', types: [I, I, B], args: [255n, 2n, 'ff00'], script: true },
  { label: 'num2bin(-1, 2) = 0180', expr: 'num2bin(a, b)', types: [I, I, B], args: [-1n, 2n, '0180'], script: true },
  { label: 'num2bin(0, 0) = ""', expr: 'num2bin(a, b)', types: [I, I, B], args: [0n, 0n, ''], script: true },
  { label: 'num2bin(-128, 1) = 80 is too narrow', expr: 'num2bin(a, b)', types: [I, I, B], args: [-128n, 1n, '80'], script: false },
  { label: 'num2bin(127, 1) = 7f', expr: 'num2bin(a, b)', types: [I, I, B], args: [127n, 1n, '7f'], script: true },
  // BM-F6: non-minimal operand into a numeric builtin aborts on chain.
  { label: 'abs(1 >> 1)', expr: 'abs(a >> b)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'min(1 >> 1, 5)', expr: 'min(a >> b, 5n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'max(1 >> 1, -5)', expr: 'max(a >> b, -5n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'clamp(1 >> 1, -5, 5)', expr: 'clamp(a >> b, -5n, 5n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'pow(1 >> 1, 2)', expr: 'pow(a >> b, 2n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'mulDiv(1 >> 1, 1, 1)', expr: 'mulDiv(a >> b, 1n, 1n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'within(1 >> 1, -1, 5)', expr: 'within(a >> b, -1n, 5n)', types: [I, I, 'boolean'], args: [1n, 1n, true], script: false },
  { label: 'sign(1 >> 1)', expr: 'sign(a >> b)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'sqrt(1 >> 1)', expr: 'sqrt(a >> b)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'gcd(1 >> 1, 6)', expr: 'gcd(a >> b, 6n)', types: [I, I, I], args: [1n, 1n, 6n], script: false },
  { label: 'log2(2 >> 1 ... non-minimal 256 >> 8)', expr: 'log2(a >> b)', types: [I, I, I], args: [256n, 8n, 0n], script: false },
  { label: 'divmod(1 >> 1, 3)', expr: 'divmod(a >> b, 3n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'safediv(1 >> 1, 3)', expr: 'safediv(a >> b, 3n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'safemod(1 >> 1, 3)', expr: 'safemod(a >> b, 3n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'percentOf(1 >> 1, 3)', expr: 'percentOf(a >> b, 3n)', types: [I, I, I], args: [1n, 1n, 0n], script: false },
  { label: 'bool(1 >> 1)', expr: 'bool(a >> b)', types: [I, I, 'boolean'], args: [1n, 1n, false], script: false },
  { label: 'split(c, 1 >> 1)', expr: 'split(c, a >> b)', types: [I, I, B, B], args: [1n, 1n, 'abcd', 'abcd'], script: false },
  { label: 'left(c, 1 >> 1)', expr: 'left(c, a >> b)', types: [I, I, B, B], args: [1n, 1n, 'abcd', ''], script: false },
  { label: 'right(c, 1 >> 1)', expr: 'right(c, a >> b)', types: [I, I, B, B], args: [1n, 1n, 'abcd', ''], script: false },
  { label: 'substr(c, 1 >> 1, 1)', expr: 'substr(c, a >> b, 1n)', types: [I, I, B, B], args: [1n, 1n, 'abcd', 'ab'], script: false },
  // controls: minimal operands keep working; num2bin's value operand is exempt.
  { label: 'abs(-4 >> 1) minimal', expr: 'abs(a)', types: [I, I, I], args: [-4n, 1n, 4n], script: true },
  { label: 'num2bin(1 >> 1, 2) = 0000', expr: 'num2bin(a >> b, 2n)', types: [I, I, B], args: [1n, 1n, '0000'], script: true },
  // reverseBytes: the script reverses at most 520 bytes.
  { label: 'reverseBytes(520 B)', expr: 'reverseBytes(c)', types: [I, I, B, B], args: [0n, 0n, bytes(520), rev(bytes(520))], script: true },
  { label: 'reverseBytes(521 B) full reverse', expr: 'reverseBytes(c)', types: [I, I, B, B], args: [0n, 0n, bytes(521), rev(bytes(521))], script: false },
  { label: 'reverseBytes(600 B) full reverse', expr: 'reverseBytes(c)', types: [I, I, B, B], args: [0n, 0n, bytes(600), rev(bytes(600))], script: false },
];

describe('D12: SDK ANF interpreter builtins agree with the compiled script', () => {
  for (const row of ROWS) {
    it(`${row.label}: script ${row.script ? 'accepts' : 'aborts'}, SDK agrees`, () => {
      const v = verdicts(row);
      expect(v.script).toBe(row.script); // the oracle is what this table claims
      expect({ sdk: v.sdk, err: v.sdkError }).toMatchObject({ sdk: v.script });
    });
  }

  it('reverseBytes > 520 B is refused with a reason, not a wrong value', () => {
    const v = verdicts(ROWS.find((r) => r.label === 'reverseBytes(600 B) full reverse')!);
    expect(v.sdkError).toMatch(/520/);
  });
});
