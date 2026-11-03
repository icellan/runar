import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compileFromANF, loadANFFromJSON } from '../index.js';

/**
 * N-087 — `compileFromANF` enforces the source validator's parentClass rules
 * and the readonly-write rule on IR, with the diagnostics shared by all seven
 * tiers (conformance/negatives/ir-parent-class-cases.json).
 *
 * Before: IR skips 02-validate/03-typecheck, so a SmartContract declaring
 * `owner` with `readonly: false` (F-107's v2-mut-stateless) got no constructor
 * slot, and `update_prop owner = x; assert(owner == x)` compiled to
 * `76767b8777`, which an attacker's key spends under strict @bsv/sdk Spend.
 * A write to a readonly or undeclared property, a stateful-only node in a
 * non-stateful contract and a raw_script outside UnsafeSmartContract all
 * compiled too. Absent parentClass (pre-F-038 IR) is inferred fail-closed:
 * StatefulSmartContract only from a stateful-only node, else
 * UnsafeSmartContract from a raw_script, else SmartContract.
 *
 * Proves: every corpus case is refused with its exact diagnostic, and the
 * accepted programs (incl. a parentClass-less P2PK and raw_script) compile.
 * Does not prove: that the six native tiers agree
 * (conformance/negatives/ir-parent-class.test.ts does), or that a declared
 * StatefulSmartContract body really enforces its state continuation — that is
 * not checked here.
 */

const CORPUS = JSON.parse(
  readFileSync(
    join(__dirname, '../../../../conformance/negatives/ir-parent-class-cases.json'),
    'utf8',
  ),
) as {
  accept: Array<{ name: string; ir: unknown }>;
  cases: Array<{ name: string; ir: unknown; error: string; match?: 'prefix' }>;
};

const compile = (ir: unknown) => compileFromANF(loadANFFromJSON(JSON.stringify(ir)));

describe('N-087: compileFromANF parentClass and readonly-write rules', () => {
  it('the corpus is non-empty', () => {
    expect(CORPUS.cases.length).toBeGreaterThanOrEqual(10);
    expect(CORPUS.accept.length).toBeGreaterThanOrEqual(3);
  });

  for (const a of CORPUS.accept) {
    it(`compiles ${a.name}`, () => {
      expect(compile(a.ir).scriptHex).not.toBe('');
    });
  }

  for (const c of CORPUS.cases) {
    it(`refuses ${c.name}`, () => {
      let message = '<accepted>';
      try {
        compile(c.ir);
      } catch (e) {
        message = (e as Error).message;
      }
      if (c.match === 'prefix') expect(message.startsWith(c.error), message).toBe(true);
      else expect(message).toBe(c.error);
    });
  }
});
