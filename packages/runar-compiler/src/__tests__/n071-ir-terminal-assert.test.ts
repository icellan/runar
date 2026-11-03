import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compileFromANF, loadANFFromJSON } from '../index.js';

/**
 * N-071 — `compileFromANF` refuses a public method that does not END with an
 * assert, with the diagnostic shared by all seven tiers.
 *
 * Before: IR skips 02-validate, so `"body": []` compiled to an EMPTY script and
 * an `if` whose else arm ended in `load_const true` compiled to a script an
 * empty signature spends (both at exit 0 through `runar compile --from-ir`).
 *
 * Proves: every case in the shared corpus is refused with its exact diagnostic,
 * and the accepted programs (a P2PK control and a both-arm `if`) still compile.
 * Does not prove: that the six native tiers agree
 * (conformance/negatives/ir-terminal-assert.test.ts does), or that an accepted
 * program is secure — ending in an assert is necessary, not sufficient.
 */

const CORPUS = JSON.parse(
  readFileSync(
    join(__dirname, '../../../../conformance/negatives/ir-terminal-assert-cases.json'),
    'utf8',
  ),
) as {
  accept: Array<{ name: string; ir: unknown }>;
  cases: Array<{ name: string; ir: unknown; error: string }>;
};

const compile = (ir: unknown) => compileFromANF(loadANFFromJSON(JSON.stringify(ir)));

describe('N-071: compileFromANF terminal-assert rule', () => {
  for (const a of CORPUS.accept) {
    it(`compiles ${a.name}`, () => {
      expect(compile(a.ir).scriptHex).not.toBe('');
    });
  }

  for (const c of CORPUS.cases) {
    it(`refuses ${c.name}`, () => {
      expect(() => compile(c.ir)).toThrow(c.error);
    });
  }
});
