import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { compile, compileFromANF, loadANFFromJSON } from '../index.js';
import { assertIrStatefulScaffolding } from '../passes/stateful-scaffold.js';

/**
 * N-101 — `compileFromANF` refuses a StatefulSmartContract program (declared,
 * or inferred per N-087) any of whose public methods lacks, reorders or alters
 * the scaffolding 04-anf-lower.ts injects: the auto-injected parameters, the
 * checkPreimage / sighash-type / deserialize_state prologue and the state
 * continuation. Diagnostics are shared by all seven tiers
 * (conformance/negatives/ir-stateful-scaffold-cases.json).
 *
 * Before: F-107's attack body relabelled StatefulSmartContract compiled to
 * `76767b8777` and the same body with no parentClass plus a dead
 * add_data_output compiled too; an attacker's key spent both under strict
 * @bsv/sdk Spend, in all seven tiers.
 *
 * Proves: every corpus case is refused with its exact diagnostic; the accepted
 * programs compile; every checked-in StatefulSmartContract golden passes the
 * check and still compiles to its golden bytes; the IR the frontend emits for
 * every golden source passes the check with constant folding on and off.
 * Does not prove: that the six native tiers agree
 * (conformance/negatives/ir-stateful-scaffold.test.ts does), or anything about
 * the user code between prologue and continuation, which stays free.
 */

const REPO = join(__dirname, '../../../..');
const CORPUS = JSON.parse(
  readFileSync(join(REPO, 'conformance/negatives/ir-stateful-scaffold-cases.json'), 'utf8'),
) as {
  accept: Array<{ name: string; ir: unknown }>;
  cases: Array<{ name: string; ir: unknown; error: string }>;
};

const compileIr = (ir: unknown) => compileFromANF(loadANFFromJSON(JSON.stringify(ir)));

const TESTS = join(REPO, 'conformance/tests');
const statefulGoldens = readdirSync(TESTS).filter((f) => {
  const p = join(TESTS, f, 'expected-ir.json');
  return existsSync(p) && (JSON.parse(readFileSync(p, 'utf8')) as { parentClass?: string }).parentClass === 'StatefulSmartContract';
});

describe('N-101: compileFromANF re-derives the StatefulSmartContract scaffolding', () => {
  it('the corpus and the stateful golden set are non-empty', () => {
    expect(CORPUS.cases.length).toBeGreaterThanOrEqual(10);
    expect(CORPUS.accept.length).toBeGreaterThanOrEqual(3);
    expect(statefulGoldens.length).toBeGreaterThanOrEqual(15);
    expect(CORPUS.cases.map((c) => c.name)).toContain('hijack-declared-stateful');
  });

  for (const a of CORPUS.accept) {
    it(`compiles ${a.name}`, () => {
      expect(compileIr(a.ir).scriptHex).not.toBe('');
    });
  }

  for (const c of CORPUS.cases) {
    it(`refuses ${c.name}`, () => {
      let message = '<accepted>';
      try {
        compileIr(c.ir);
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toBe(c.error);
    });
  }

  for (const fixture of statefulGoldens) {
    it(`the ${fixture} golden passes and compiles to its golden bytes`, () => {
      const dir = join(TESTS, fixture);
      const ir = loadANFFromJSON(readFileSync(join(dir, 'expected-ir.json'), 'utf8'));
      expect(() => assertIrStatefulScaffolding(ir)).not.toThrow();
      const hex = readFileSync(join(dir, 'expected-script.hex'), 'utf8').trim().toLowerCase();
      expect(compileFromANF(ir, { disableConstantFolding: true }).scriptHex.toLowerCase()).toBe(hex);
    });
  }

  // Every source of every stateful golden, in all nine formats, plus every
  // StatefulSmartContract under examples/ts: the IR the frontend emits must
  // pass the check with constant folding on and off.
  const sources: string[] = [];
  for (const fixture of statefulGoldens) {
    const { sources: map } = JSON.parse(readFileSync(join(TESTS, fixture, 'source.json'), 'utf8')) as { sources: Record<string, string> };
    for (const rel of Object.values(map)) sources.push(join(TESTS, fixture, rel));
  }
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.runar.ts') && readFileSync(p, 'utf8').includes('StatefulSmartContract')) sources.push(p);
    }
  };
  walk(join(REPO, 'examples/ts'));

  it('the frontend source set is non-empty', () => {
    expect(sources.length).toBeGreaterThanOrEqual(100);
  });

  for (const file of [...new Set(sources)]) {
    for (const fold of [false, true]) {
      it(`the frontend's ${fold ? 'fold-ON' : 'fold-OFF'} IR for ${file.slice(REPO.length + 1)} passes`, () => {
        const result = compile(readFileSync(file, 'utf8'), {
          fileName: file,
          disableConstantFolding: !fold,
        });
        expect(result.success, JSON.stringify(result.diagnostics)).toBe(true);
        expect(() => assertIrStatefulScaffolding(result.anf!)).not.toThrow();
      });
    }
  }
});
