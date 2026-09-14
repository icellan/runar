/**
 * R-288 (CL-GAP-078): the BIP-143 preimage field offsets are hand-maintained in
 * three places in `05-stack-lower.ts`, and the same magic number is re-derived
 * in prose at each one.
 *
 * Four sites push the literal `52n` — the fixed tail that follows scriptCode in
 * a BIP-143 sighash preimage — each with its own comment doing the arithmetic
 * again, and in two different orders:
 *
 *     lowerComputeStateOutputHash   `52n` // 8 (amount) + 44 (tail)
 *     lowerDeserializeState         `52n` // amount 8 + nSequence 4 + hashOutputs 32 + nLocktime 4 + sighashType 4
 *     extractAmount                 `52n` // 44 + 8 = 52. Amount starts 52 bytes from end
 *     extractScriptCode             `52n` // size - 52 = scriptCode length
 *
 * Nothing is wrong with the emitted scripts — all four agree today. The defect
 * is that they agree by coincidence of four independent hand-derivations, and
 * a BIP-143 layout change (or a typo) has four places to be wrong in.
 *
 * This test pins the two properties that make that impossible rather than
 * unlikely: the tail size is DERIVED from the named field widths rather than
 * asserted as a number, and no site pushes the literal any more.
 *
 * The emitted bytes are unchanged — the constant evaluates to the same 52 — so
 * the conformance goldens are the proof that this refactor moved nothing.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FILE = 'packages/runar-compiler/src/passes/05-stack-lower.ts';
const source = readFileSync(join(ROOT, FILE), 'utf-8');

/** Lines that are code, not comment — the duplication only matters in code. */
function codeLines(text: string): string[] {
  return text
    .split('\n')
    .filter((l) => {
      const t = l.trim();
      return t.length > 0 && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*');
    });
}

describe('R-288: the BIP-143 tail size is defined once and derived', () => {
  it('each named field width is declared exactly once', () => {
    for (const name of [
      'BIP143_AMOUNT_BYTES',
      'BIP143_NSEQUENCE_BYTES',
      'BIP143_HASH_OUTPUTS_BYTES',
      'BIP143_NLOCKTIME_BYTES',
      'BIP143_SIGHASH_TYPE_BYTES',
    ]) {
      const declarations = codeLines(source).filter((l) => l.includes(`const ${name}`));
      expect(declarations.length, `${name} should be declared exactly once`).toBe(1);
    }
  });

  it('the tail size is a sum of the field widths, not a literal', () => {
    const decl = codeLines(source).find((l) => l.includes('const BIP143_TAIL_WITH_AMOUNT_BYTES'));
    expect(decl, 'BIP143_TAIL_WITH_AMOUNT_BYTES is not declared').toBeTruthy();
    // The whole point: the 52 must come out of the addition, so a layout change
    // is one edit rather than four.
    expect(decl, 'the tail size is still written as a literal').not.toMatch(/=\s*52\b/);
    for (const part of [
      'BIP143_AMOUNT_BYTES',
      'BIP143_TAIL_AFTER_AMOUNT_BYTES',
    ]) {
      expect(decl!, `the tail size does not add ${part}`).toContain(part);
    }
  });

  it('and it really is 52, so the emitted scripts cannot move', () => {
    // Evaluate the declarations out of the source rather than exporting
    // compiler internals just to be measured.
    // Declarations span several lines, so scan the whole source with comments
    // stripped rather than line by line.
    const stripped = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
    const nums: Record<string, number> = {};
    const decl = /const (BIP143_\w+)\s*=\s*([^;]+);/g;
    let m: RegExpExecArray | null;
    while ((m = decl.exec(stripped)) !== null) {
      const expr = m[2]!.replace(/BIP143_\w+/g, (k) => String(nums[k] ?? NaN));
      // eslint-disable-next-line no-new-func
      nums[m[1]!] = Number(new Function(`return (${expr});`)());
    }
    expect(nums.BIP143_TAIL_AFTER_AMOUNT_BYTES, 'nSeq 4 + hashOutputs 32 + nLocktime 4 + sighashType 4').toBe(44);
    expect(nums.BIP143_TAIL_WITH_AMOUNT_BYTES, 'amount 8 + the 44-byte tail').toBe(52);
  });

  it('no site pushes the tail size as a bare literal any more', () => {
    const offenders = codeLines(source).filter((l) => /value:\s*52n/.test(l));
    expect(
      offenders.map((l) => l.trim()),
      'these still hardcode the BIP-143 tail size instead of using the constant',
    ).toEqual([]);
  });
});
