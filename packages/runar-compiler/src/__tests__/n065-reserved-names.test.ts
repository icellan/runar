import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile, compileFromANF, loadANFFromJSON } from '../index.js';

/**
 * N-065 / N-060 — a user identifier spelled like a name the compiler mints is
 * refused, with one diagnostic shared verbatim by all seven tiers.
 *
 * Before: `let t2: bigint = p; assert(p > 0n); if (c) { t2 = p; }
 * assert(t2 + 1n === 1n);` compiled (folding OFF and ON) to a script that
 * accepts p = 1, c = false, which the source rejects: `0n` lowers to the ANF
 * temp `t2`, and the final guard read the temp. Every other minted family
 * (stack-lowering slots, FixedArray slots, auto-injected parameters) was
 * accepted the same way, and `--ir` accepted parameters, properties, bindings
 * and references named after stack lowering's own slots (N-060).
 *
 * Proves: every source case in the shared corpus
 * (conformance/negatives/reserved-names-cases.json) is refused by the TS
 * frontend with the shared sentence while its renamed twin compiles; a
 * stateless contract's own `txPreimage` parameter still compiles; every `--ir`
 * case is refused by `loadANFFromJSON` and the accepted IR (ANF temps and
 * `__merge$` as binding names, `txPreimage` as a parameter) still compiles.
 * Does not prove: the other six tiers (conformance/negatives/reserved-names.test.ts
 * does), or the on-chain effect (the same file runs the Spend oracle).
 */

interface SourceCase { name: string; file: string; src: string; twin: string; error: string }
interface IrCase { name: string; ir: unknown; error: string }

const CORPUS = JSON.parse(
  readFileSync(join(__dirname, '../../../../conformance/negatives/reserved-names-cases.json'), 'utf8'),
) as {
  source: { accept: Array<{ name: string; file: string; src: string }>; cases: SourceCase[] };
  ir: { accept: Array<{ name: string; ir: unknown }>; cases: IrCase[] };
};

describe('N-065: compiler-reserved names in source', () => {
  for (const c of CORPUS.source.cases) {
    it(`refuses ${c.name}`, () => {
      const r = compile(c.src, { fileName: c.file, disableConstantFolding: true });
      expect(r.success).toBe(false);
      expect(r.diagnostics.map((d) => d.message)).toContain(c.error);
    });

    it(`compiles the renamed twin of ${c.name}`, () => {
      const r = compile(c.twin, { fileName: c.file, disableConstantFolding: true });
      expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    });
  }

  for (const a of CORPUS.source.accept) {
    it(`accepts ${a.name}`, () => {
      const r = compile(a.src, { fileName: a.file });
      expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    });
  }
});

describe('N-060 / N-065: compiler-reserved names in --ir', () => {
  for (const c of CORPUS.ir.cases) {
    it(`refuses ${c.name}`, () => {
      expect(() => loadANFFromJSON(JSON.stringify(c.ir))).toThrow(c.error);
    });
  }

  for (const a of CORPUS.ir.accept) {
    it(`accepts ${a.name}`, () => {
      const hex = compileFromANF(loadANFFromJSON(JSON.stringify(a.ir))).scriptHex;
      expect(hex).toBe('00ac');
    });
  }
});
